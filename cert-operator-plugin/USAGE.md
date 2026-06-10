# cert-operator 完整使用手册（AI 阅读版）

## 目录

1. [插件工作流](#1-插件工作流)
2. [get_sub_cert 详解](#2-get_sub_cert-详解)
3. [ssh_with_cert 详解](#3-ssh_with_cert-详解)
4. [sudo 权限机制](#4-sudo-权限机制)
5. [错误排查大全](#5-错误排查大全)
6. [CLI 回退方案](#6-cli-回退方案)
7. [目标服务器部署](#7-目标服务器部署)
8. [卸载与恢复](#8-卸载与恢复)
9. [全手动回退：原始 HTTP 请求](#9-全手动回退原始-http-请求)

---

## 1. 插件工作流

```
┌─────────────────────────────────────────────────────────┐
│  get_sub_cert                                           │
│  用户提供 TOTP → AI 调用 API → 获取 SSH 证书 → 本地保存 │
│  返回值: cert_path（下一步用）                            │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  ssh_with_cert                                          │
│  证书路径 → 自动加载到 agent → SSH -A 到目标服务器       │
│  → 执行命令（sudo 由目标服务器 wrapper 拦截处理）          │
│  返回值: stdout + exit_code                              │
└─────────────────────────────────────────────────────────┘
```

## 2. get_sub_cert 详解

### 参数

| 参数 | 必填 | 类型 | 默认值 | 说明 |
|------|------|------|--------|------|
| `server` | ✅ | URL | — | CA 服务器地址，如 `https://121.196.206.66:8443` |
| `totp_code` | ✅ | string(6) | — | 用户提供的 6 位 TOTP 验证码 |
| `cert_name` | ✅ | 文件名 | — | 标识这个证书用途，如 `web-server`。只能含字母数字和 `-_.` |
| `group_name` | | string | `default` | 组名，决定证书中写入哪些 SSH 权限 |
| `user_name` | | string | 服务端决定 | SSH 登录用户名（root / aibot 等） |
| `ca_cert_path` | | 路径 | `~/.hermes/certs/ca-https-cert.pem` | CA 自签 HTTPS 证书（首次需配置） |
| `client_cert` | | 路径 | `~/.hermes/certs/client.cert` | mTLS 客户端证书 |
| `client_key` | | 路径 | `~/.hermes/certs/client.key` | mTLS 客户端私钥 |

### 返回

```json
{
  "success": true,
  "cert_path": "/home/yyx/.hermes/certs/web-server",
  "cert_name": "web-server",
  "serial": "3",
  "expires_at": "2026-06-10T02:54:56Z"
}
```

**关键字段：** `cert_path` 是下一步的唯一输入。

### 证书文件说明

get_sub_cert 会写两个文件到 `~/.hermes/certs/`：

```
~/.hermes/certs/<cert_name>              ← SSH 私钥 (权限 600)
~/.hermes/certs/<cert_name>-cert.pub     ← SSH 证书 (权限 644)
```

SSL 方式连接时，ssh 会自动发现同目录下的证书文件。

## 3. ssh_with_cert 详解

### 参数

| 参数 | 必填 | 类型 | 默认值 | 说明 |
|------|------|------|--------|------|
| `host` | ✅ | IP/域名 | — | 目标服务器地址 |
| `user` | ✅ | string | — | SSH 用户名，必须与 get_sub_cert 一致 |
| `cert_path` | ✅ | 路径 | — | get_sub_cert 返回的 `cert_path` |
| `command` | | string | （生成连接命令） | 要执行的远程命令 |
| `port` | | int | 22 | SSH 端口 |

### 内部行为

AI 调用 ssh_with_cert 时底层等价于：

```bash
# 1. 启动新 ssh-agent（用完自动杀死）
eval $(ssh-agent -s)

# 2. 加载私钥和证书到 agent
ssh-add ~/.hermes/certs/<cert_name>

# 3. SSH 连接（-A 转发 agent 供远程 cert-sudo-check 验证）
ssh -A -i ~/.hermes/certs/<cert_name> -p <port> user@host '<command>'

# 4. SSH 结束后自动杀死 agent（无残留）
```

### 返回

```json
{
  "success": true,
  "output": "root\nFilesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   12G   28G  31% /",
  "exit_code": 0
}
```

### 无命令模式

不传 `command` 时，返回一条 SSH 命令字符串供用户手动执行：

```json
{
  "success": true,
  "output": "ssh -A -i /home/yyx/.hermes/certs/web-server -p 22 root@121.196.206.66",
  "exit_code": 0
}
```

## 4. sudo 权限机制

### 架构

```
本地机器 (插件/CLI)              目标服务器
─────────────────               ──────────
ssh-agent ─── ssh -A ──────────→ 转发 agent socket
  │                               │
  │                        SSH_AUTH_SOCK=xxx (仅 bash 可见)
  │                               │
证书加载到 agent                   │
sudo@cert-operator 扩展            │
  │                               │
  │                        sudo -n xxx
  │                            → /usr/bin/sudo (wrapper)
  │                              → 写 socket 路径到 /tmp/.cert-sudo-sock
  │                              → 调 cert-sudo-check
  │                                → 通过 $SSH_AUTH_SOCK 连 agent
  │                                → 查证书 → 有 sudo 扩展？✅
  │                              → exec /usr/bin/_sudo xxx (去掉 -n)
  │                                → PAM → cert-sudo-check
  │                                  → 读 /tmp/.cert-sudo-sock → 再次确认
  │                                → 免密执行
```

### sudo wrapper 工作细节

当 AI 调用 `ssh_with_cert` 执行 `sudo -n xxx` 时：

1. 目标服务器上的 `/usr/bin/sudo`（wrapper 脚本）截获
2. wrapper 检测到 `-n` 标志
3. wrapper 将 `SSH_AUTH_SOCK` 写入 `/tmp/.cert-sudo-sock`（供 PAM 读取）
4. wrapper 调用 `cert-sudo-check` → 通过 agent socket 查询证书
5. 验证通过 → `exec /usr/bin/_sudo xxx`（去掉了 `-n`，不输出 needpassword）
6. 真 sudo 触发 PAM → `cert-sudo-check` 再次验证 → 读取 `/tmp/.cert-sudo-sock`
7. 放行

**关键依赖：** `ssh -A`（agent forwarding）。没有 `-A`，远程就收不到 agent socket，sudo 验证失败。

### sudo 组配置

| 组名 | SSH 用户 | sudo 权限 |
|------|---------|----------|
| `root` | root | ✅ 全权 |
| `aibot-sudo` | aibot | ✅ 全权 |
| `aibot-nosudo` | aibot | ❌ 无 sudo |

### 证书有效期

- 默认 60 分钟（CA 服务器签发时设定）
- 过期后 `sudo -n` 直接拒绝，`sudo` 回退到密码
- 需要重新调用 `get_sub_cert` 获取新证书

## 5. 错误排查大全

### 5.1 get_sub_cert 阶段

#### E1. TOTP 验证失败

```
错误信息: "TOTP验证失败" 或 "invalid totp"
```

| 原因 | 概率 | 处理 |
|------|------|------|
| 验证码已过期（30 秒窗口） | 高 | 让用户刷新 TOTP 重新提供 |
| 输入错误（数字看错） | 中 | 让用户仔细核对重新输入 |
| 手机时间与 CA 服务器不同步 | 低 | 让用户在 TOTP 应用中重新同步时间 |
| 用户在错误的应用中读取码 | 低 | 确认用户打开的是正确应用的 TOTP |

**排查步骤：**
1. 确认 totp_code 是 6 位数字
2. 让用户关闭并重新打开 TOTP 应用，获取新码重试
3. 如果仍然失败，尝试连续 2 次（TOTP 有 ±1 步的时间窗口）

#### E2. CA 服务器连接失败

```
错误信息: "无法读取 CA 证书" 或 "tls: first record does not look like a TLS handshake"
```

| 原因 | 概率 | 处理 |
|------|------|------|
| CA 服务器地址错误 | 中 | 确认 `server` 参数的前缀是 `https://`，端口正确（通常是 8443） |
| 网络不通/防火墙 | 中 | 用 ping / telnet 测试连通性 |
| CA 服务器宕机 | 低 | 联系管理员 |
| DNS 解析失败 | 低 | 改用 IP 地址直连 |

**排查步骤：**
1. 先确认 CA 服务器是否在线：`curl -sk https://<server>:8443/api/health`
2. 尝试不带 mTLS 的请求：`curl -sk https://<server>:8443/api/version`

#### E3. 证书文件已存在冲突

```
错误信息: "cert_name 只能包含字母数字和-_."
```

| 原因 | 处理 |
|------|------|
| `cert_name` 包含特殊字符或路径分隔符 | 只使用 `a-z` `A-Z` `0-9` `-` `_` `.` |
| 想为同一台服务器重新获取证书 | 使用不同的 `cert_name`，或先用 CLI 删除旧文件 |

#### E4. 429 Too Many Requests

```
错误信息: "429" 或 "rate limit exceeded"
```

| 原因 | 处理 |
|------|------|
| 短时间内请求次数过多 | 等待 5 分钟后重试 |

#### E5. mTLS 证书无效

```
错误信息: "bad certificate" 或 "tls: unknown certificate"
```

| 原因 | 处理 |
|------|------|
| client.cert/client.key 与服务器不匹配 | 联系管理员重新分发客户端证书 |
| 文件权限不正确 | 确认 client.key 权限为 600 |

### 5.2 ssh_with_cert 阶段

#### E6. SSH 连接被拒绝

```
错误信息: "Connection refused" 或 "port 22: Connection refused"
```

| 原因 | 处理 |
|------|------|
| 目标服务器 SSH 服务未运行 | 确认 sshd 正在监听：`systemctl status sshd` |
| 端口错误 | 确认使用了正确的 SSH 端口，用 `--port N` 指定 |
| 防火墙拦截 | 确认目标服务器 22 端口对外开放 |

#### E7. SSH 认证失败

```
错误信息: "Permission denied (publickey)"
```

| 原因 | 概率 | 处理 |
|------|------|------|
| 证书已过期 | 高 | 重新调用 get_sub_cert 获取新证书 |
| 目标服务器未配置 TrustedUserCAKeys | 中 | 检查服务器 `/etc/ssh/sshd_config` 是否有 `TrustedUserCAKeys` |
| CA 公钥与签发证书的 CA 不匹配 | 中 | 重新获取证书（参考 E10） |
| cert_name 对应的证书文件不存在 | 低 | 确认 cert_path 参数正确 |
| SSH 用户与证书 principal 不匹配 | 中 | 确保证书中的 principal 包含登录用户名 |

**排查步骤：**
1. 先检查证书有效期：`ssh-keygen -L -f <cert_path>-cert.pub` 看 `Valid` 字段
2. 再检查签发 CA：`ssh-keygen -L -f <cert_path>-cert.pub` 看 `Signing CA` 字段
3. 在目标服务器上手动测试：`ssh -i <cert_path> -p <port> user@host`

#### E8. SSH 连接超时

```
错误信息: "Connection timed out" 或 "Operation timed out"
```

| 原因 | 处理 |
|------|------|
| 目标服务器 IP/端口不对 | 确认 IP 和端口 |
| 防火墙/安全组拦截 | 联系管理员开放端口 |
| 目标服务器不在线 | 检查服务器运行状态 |

#### E9. 命令执行但 sudo 提示输入密码

```
输出: 正确输出了命令结果，但 sudo: a password is required
```

| 原因 | 处理 |
|------|------|
| **ssh 调用未加 `-A`**（最常见） | ssh_with_cert 必须使用 `-A` 参数 |
| 本地没有 ssh-agent 运行 | ssh_with_cert 会自动启动 agent |
| 证书未加载到 agent | ssh_with_cert 会自动执行 `ssh-add` |
| 目标服务器未部署 sudo wrapper | 在目标服务器上运行 `deploy-sudo-wrapper.sh` |
| 目标服务器 CA 公钥不匹配 | 重新部署 CA 公钥或重签证书 |

**排查步骤：**
1. 确认 `ssh_with_cert` 传入了 `cert_path`（从 get_sub_cert 返回值获取）
2. 手动测试：`ssh -A -i <cert_path> -p <port> user@host 'echo $SSH_AUTH_SOCK'`
   - 如果 `SSH_AUTH_SOCK` 为空 → agent 转发失败
   - 如果 socket 存在 → 继续检查证书
3. 远程测试证书：`ssh -A user@host 'ssh-add -L'` 应该能看到证书行
4. 远程测试 sudo wrapper：`ssh -A user@host 'sudo -n whoami'`

#### E10. CA 重置后证书签名不匹配

```
现象: get_sub_cert 成功，证书未过期，但 sudo 始终要求密码
      ssh-keygen -L 显示 CA 指纹与服务器不同
```

| 原因 | 处理 |
|------|------|
| 管理员执行了 `reset ca` 或 `reinit`，CA 密钥对更换 | 删除所有旧证书 → 重新 get_sub_cert |

**排查：**
```bash
# 本地证书的签名 CA
ssh-keygen -L -f ~/.hermes/certs/<cert>-cert.pub | grep 'Signing CA'

# 目标服务器当前的 CA 公钥指纹
ssh-keyscan -p <port> <host> 2>/dev/null | ssh-keygen -lf - 2>/dev/null
# 或从 CA 服务器获取：
curl -sk https://<ca-server>:8443/api/info | jq .ca_public
```

**修复：**
```bash
# 1. 删除旧证书
rm ~/.hermes/certs/<cert_name> ~/.hermes/certs/<cert_name>-cert.pub

# 2. 重新获取
get_sub_cert(server="...", totp_code="...", cert_name="<cert_name>")
```

#### E11. dpkg-divert 未执行（sudo wrapper 不存在）

```
现象: 远程执行 sudo -n xxx → needpassword
      检查远程 /usr/bin/sudo 不是 wrapper 脚本（文件大小不同）
```

| 原因 | 处理 |
|------|------|
| 目标服务器从未运行过 deploy-sudo-wrapper.sh | 在目标服务器上以 root 运行部署脚本 |
| 服务器被重新部署过 | 重新运行 deploy-sudo-wrapper.sh |
| apt 重装 sudo 包时覆盖了 wrapper | 重新运行 deploy-sudo-wrapper.sh（dpkg-divert 保护机制未生效） |

**排查：**
```bash
# 远程检查
ssh user@host "head -3 /usr/bin/sudo"
# 如果是 ELF 二进制 → wrapper 未安装（文件开头是 7f 45 4c 46）
# 如果是 #!/bin/bash → wrapper 已安装
```

**修复：**
```bash
# 以 root 重新部署
ssh user@host "sudo bash deploy-sudo-wrapper.sh"
```

#### E12. cert-sudo-check 未安装或版本不匹配

```
现象: 远程 sudo -n xxx → "sudo: cert-sudo-check not found, need password"
```

| 原因 | 处理 |
|------|------|
| /usr/local/bin/cert-sudo-check 不存在 | 重新运行 deploy-sudo-wrapper.sh |
| cert-sudo-check 太旧（v3 以下） | 更新 cert-sudo-check 为 v9 |

#### E13. 证书文件权限错误

```
现象: ssh -i <key> 出现 "Permissions 0644 for '...' are too open"
```

| 原因 | 处理 |
|------|------|
| 私钥文件权限不是 600 | get_sub_cert 自动设置 600，但如果手动复制过会变 |
| 修复 | `chmod 600 ~/.hermes/certs/<cert_name>` |

#### E14. shell 注入 / 命令转义问题

```
现象: 执行复杂命令时结果异常或语法错误
```

| 原因 | 处理 |
|------|------|
| 命令中包含特殊字符（`$` `\` `"` `` ` ``） | SSH 命令会经 shell 解析，远程端可能被转义 |
| 管道、重定向在本地被解析 | 将整个命令用单引号包裹 |

**安全做法：**
```bash
# 简单命令直接传
cert-operator ssh host user key "ls -la"

# 复杂命令使用 base64 避免转义
CMD=$(echo -n '&& || | ; $()' | base64)
cert-operator ssh host user key "eval \"\$(echo $CMD | base64 -d)\""
```

### 5.3 部署阶段

#### E15. dpkg-divert 安装失败

```
错误: "dpkg-divert: error: mismatch on divert-to"
```

| 原因 | 处理 |
|------|------|
| 之前有未完成的 diversion | `dpkg-divert --remove /usr/bin/sudo` 清理后重试 |
| /usr/bin/_sudo 已被其他包占用 | 检查 `dpkg-divert --list` 找出冲突 |

#### E16. PAM 配置语法错误

```
错误: "sudo: /etc/pam.d/sudo: syntax error"
```

| 原因 | 处理 |
|------|------|
| 手动编辑 PAM 文件出错 | `visudo -c` 检查语法，修复后重试 |
| deploy.sh 多次运行插入重复行 | 手动清理重复行，只保留一条 `auth sufficient pam_exec.so ...` |

#### E17. visudo 权限错误

```
错误: "/etc/sudoers.d/99-cert-operator: bad permissions, should be mode 0440"
```

| 原因 | 处理 |
|------|------|
| env_keep 配置文件权限错误 | `chmod 0440 /etc/sudoers.d/99-cert-operator` |

### 5.4 SSL/TLS 问题

#### E18. 自签证书警告

```
错误: "x509: certificate signed by unknown authority"
```

| 原因 | 处理 |
|------|------|
| CA 使用自签 HTTPS 证书 | get_sub_cert 需要传入 `ca_cert_path` 参数指向 CA 的 HTTPS 证书 |

**处理：**
```bash
# 首次使用需要先获取 CA 的 HTTPS 证书
scp root@ca-server:/opt/ca_server/data/https_cert.pem ~/.hermes/certs/ca-https-cert.pem
# 之后的 get_sub_cert 调用会自动使用这个证书
```

## 6. CLI 回退方案

当插件 `ssh_with_cert` 无法完成任务时（如需要交互式 shell、本地文件传输等），可以用 `cert-operator` CLI 作为回退。

### 安装 CLI

```bash
# 下载二进制
wget https://github.com/user/cert-operator/releases/download/v2.3.0/cert-operator-v2.3.0-linux-x86_64.tar.gz
tar -xzf cert-operator-v2.3.0-linux-x86_64.tar.gz
chmod +x cert-operator
sudo mv cert-operator /usr/local/bin/

# 验证
cert-operator version
# 输出: cert-operator v2.3.0
```

### CLI 命令一览

```bash
cert-operator get-cert <server> <totp> <cert_name> [flags]    # 获取证书
cert-operator ssh <host> <user> <key> [command] [--port N]    # SSH 连接
cert-operator deploy [script]                                  # 部署客户端证书（很少用）
cert-operator version                                          # 显示版本
```

### get-cert 用法

```bash
# 基本用法
cert-operator get-cert https://121.196.206.66:8443 482901 my-server

# 指定组和用户
cert-operator get-cert https://121.196.206.66:8443 482901 my-server \
    --group root \
    --user root

# 覆盖默认证书路径
cert-operator get-cert https://121.196.206.66:8443 482901 my-server \
    --ca-cert /path/to/ca-https-cert.pem \
    --client-cert /path/to/client.cert \
    --client-key /path/to/client.key
```

**注意：** TOTP 码从命令行传入后 `ps` 可见，建议使用后清除 shell 历史。

### ssh 用法

```bash
# 基本命令
cert-operator ssh 121.196.206.66 root ~/.hermes/certs/my-server "df -h"

# 指定端口
cert-operator ssh 121.196.206.66 root ~/.hermes/certs/my-server \
    "systemctl status nginx" --port 2222

# 无命令模式：生成 ssh 命令字符串
cert-operator ssh 121.196.206.66 root ~/.hermes/certs/my-server
# 输出: ssh -A -i ~/.hermes/certs/my-server -p 22 root@121.196.206.66
```

**CLI ssh 行为：**
- 自动启动 ssh-agent（每次新启动）
- 自动加载证书到 agent
- 自动使用 `-A`（agent forwarding）
- 命令执行后自动杀死 agent（无残留）

### 手动 SSH 回退（当 CLI 不可用时）

```bash
# 1. 手动启动 agent
eval $(ssh-agent -s)

# 2. 加载证书
ssh-add ~/.hermes/certs/my-server

# 3. SSH 连接（必须加 -A）
ssh -A -i ~/.hermes/certs/my-server -p 22 root@121.196.206.66

# 4. 结束后清理
ssh-add -D
eval $(ssh-agent -k)
```

### 本地证书管理

```bash
# 查看已获取的证书
ls -la ~/.hermes/certs/

# 查看证书详细信息（有效期、权限等）
ssh-keygen -L -f ~/.hermes/certs/my-server-cert.pub

# 删除过期证书
rm ~/.hermes/certs/old-cert ~/.hermes/certs/old-cert-cert.pub

# 查看 agent 中已加载的证书
ssh-add -L
```

## 7. 目标服务器部署

### 部署 sudo wrapper

在目标服务器上执行（一次 root 权限）：

```bash
# 1. 上传部署文件到目标服务器
scp deploy-sudo-wrapper.sh sudo-wrapper cert-sudo-check root@target:/tmp/

# 2. 在目标服务器上执行部署
ssh root@target "bash /tmp/deploy-sudo-wrapper.sh"
```

部署脚本会自动：

| 步骤 | 操作 | 说明 |
|------|------|------|
| 1 | 安装 cert-sudo-check | 到 `/usr/local/bin/` |
| 2 | 检查 CA 公钥 | 默认 `/opt/ca_server/data/ca_key.pub` |
| 3 | dpkg-divert | 把 `/usr/bin/sudo` 重命名为 `/usr/bin/_sudo` |
| 4 | 安装 sudo-wrapper | 到 `/usr/bin/sudo` |
| 5 | 配置 PAM | 在 `/etc/pam.d/sudo` 添加 `pam_exec.so cert-sudo-check` |

### 部署后验证

```bash
# 验证所有组件
ls -la /usr/bin/sudo           # 应该是 wrapper 脚本，约 1.4KB
ls -la /usr/bin/_sudo          # 应该是真 sudo 二进制，约 232KB，有 setuid
head -3 /etc/pam.d/sudo        # 应包含 cert-sudo-check
dpkg-divert --list             # 应显示 /usr/bin/sudo → /usr/bin/_sudo

# 验证 sudo 功能
sudo --version                 # 应正常显示版本号
sudo -n whoami                 # 无证书时输出 needpassword
```

### 部署 CA 公钥

```bash
# 从 CA 服务器获取
scp root@ca-server:/opt/ca_server/data/ca_key.pub /opt/ca_server/data/ca_key.pub

# 配置 SSH 信任
cp /opt/ca_server/data/ca_key.pub /etc/ssh/ca_key.pub
echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### 重新部署（升级场景）

重新运行 `deploy-sudo-wrapper.sh` 是安全的。它会：
- 覆盖更新 `cert-sudo-check` 到最新版本
- 覆盖更新 `sudo-wrapper` 到最新版本
- 不会重复添加 PAM 行（已有则跳过）
- 不会重复执行 dpkg-divert（已有则跳过）

## 8. 卸载与恢复

```bash
# 一键卸载（清除所有痕迹）
sudo bash deploy-sudo-wrapper.sh --uninstall
```

卸载脚本会：

| 操作 | 说明 |
|------|------|
| 恢复 `/usr/bin/sudo` | 从 dpkg-divert 恢复真 sudo |
| 删除 cert-sudo-check | 移除 `/usr/local/bin/cert-sudo-check` |
| 清理 PAM 配置 | 从 `/etc/pam.d/sudo` 移除 cert-sudo-check 行 |
| 清理临时文件 | 删除 `/tmp/.cert-sudo-sock` `/etc/sudoers.d/99-cert-operator` |
| 双重保险 | 如果 dpkg-divert 恢复失败，直接从 `_sudo` mv 回 `sudo` |

### 卸载后验证

```bash
ls -la /usr/bin/sudo           # 应恢复为真 sudo 二进制（232KB, setuid）
ls -la /usr/bin/_sudo          # 不应存在
/usr/bin/sudo --version        # 应正常
sudo -n whoami                 # 应提示 needpassword（正常运行）
```

### 极端情况：sudo 完全丢失

如果卸载后 `/usr/bin/sudo` 不存在：

```bash
# 方式1: 从包修复
apt download sudo
dpkg-deb --fsys-tarfile sudo_*.deb | tar xf - ./usr/bin/sudo
cp usr/bin/sudo /usr/bin/sudo
chmod 4755 /usr/bin/sudo

# 方式2: 重新安装
apt reinstall -y sudo
```

## 9. 全手动回退：原始 HTTP 请求

当插件（`get_sub_cert` / `ssh_with_cert`）和 CLI（`cert-operator`）都不可用时，
可以用 `curl` 直接调用 CA 服务器 API 完成所有操作。

### 9.1 安全说明

服务端 **默认强制 mTLS**（`tls.RequireAndVerifyClientCert`）。所有 API 请求（包括 `/api/health` 和 `/api/version`）都需要：

| 条件 | 说明 |
|------|------|
| **HTTPS** | TLS 1.2+ 加密传输 |
| **mTLS（默认开启）** | 请求方需提供客户端证书（`client.cert` / `client.key`） |
| `--no-mtls` 标志 | 可在服务端关闭 mTLS（此时无需客户端证书） |

因此下面所有手动 curl 示例都以**带 mTLS**为默认。如果服务端使用 `--no-mtls` 启动，去掉 `--cert` 和 `--key` 参数即可。

### 9.2 健康检查

```bash
# 默认（mTLS + 自签 CA 证书）
curl -sk \
  --cert client.cert \
  --key client.key \
  https://ca-server:8443/api/health

# 如果服务端关闭了 mTLS（--no-mtls）
curl -sk https://ca-server:8443/api/health

# 如果 CA 使用受信的 HTTPS 证书（非自签）
curl \
  --cert client.cert \
  --key client.key \
  https://ca-server:8443/api/health
```

**正常响应：** `{"status":"ok"}`

### 9.3 获取证书

#### 默认：mTLS + 自签 CA（最常见）

```bash
curl -sk \
  --cert ~/.hermes/certs/client.cert \
  --key ~/.hermes/certs/client.key \
  https://ca-server:8443/api/get-cert \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"totp":"123456","group":"root","user":"root"}'
```

#### 无 mTLS（仅当服务端用 --no-mtls 启动）

```bash
curl -sk https://ca-server:8443/api/get-cert \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"totp":"123456","group":"root","user":"root"}'
```

#### mTLS + 受信 CA（非自签）

```bash
curl \
  --cacert ~/.hermes/certs/ca-https-cert.pem \
  --cert ~/.hermes/certs/client.cert \
  --key ~/.hermes/certs/client.key \
  https://ca-server:8443/api/get-cert \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"totp":"123456","group":"root","user":"root"}'
```

#### 请求体格式

```json
{
  "totp": "123456",            // 必填，6 位 TOTP 码
  "group": "root",             // 选填，组名
  "user": "root"               // 选填，SSH 用户名
}
```

#### 成功响应

```json
{
  "success": true,
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "ssh_cert": "ssh-ed25519-cert-v01@openssh.com AAAAI...",
  "serial": "3",
  "expires_at": "2026-06-10T02:54:56Z"
}
```

#### 失败响应

```json
{"success": false, "error": "TOTP验证失败"}
{"success": false, "error": "组 root 不存在"}
```

### 9.4 从 API 响应提取并保存证书

```bash
# 1. 获取证书（保存完整 JSON 响应）
curl -sk -X POST https://ca-server:8443/api/get-cert \
  -H "Content-Type: application/json" \
  -d '{"totp":"123456","group":"root","user":"root"}' \
  > /tmp/cert-response.json

# 2. 提取私钥和证书
jq -r '.ssh_private_key' /tmp/cert-response.json > ~/.ssh/my-key
jq -r '.ssh_cert' /tmp/cert-response.json > ~/.ssh/my-key-cert.pub

# 3. 设置权限
chmod 600 ~/.ssh/my-key
chmod 644 ~/.ssh/my-key-cert.pub

# 4. 验证证书
ssh-keygen -L -f ~/.ssh/my-key-cert.pub
```

没有 `jq` 时手动提取：

```bash
# 手动从 JSON 复制私钥（从 "-----BEGIN" 到 "-----END"）
# 然后保存到文件
chmod 600 ~/.ssh/my-key

# 手动复制证书行（ssh-ed25519-cert 开头）
# 保存到 ~/.ssh/my-key-cert.pub
```

### 9.5 用手动获取的证书 SSH

```bash
# 启动 agent
eval $(ssh-agent -s)

# 加载证书
ssh-add ~/.ssh/my-key

# SSH 连接（必须加 -A）
ssh -A -i ~/.ssh/my-key -p 22 root@target-server

# 测试 sudo
sudo -n whoami   # 应为 root

# 退出后清理 agent
ssh-add -D
eval $(ssh-agent -k)
```

如果不启动 agent（即不使用 `-A`），仍可以 SSH 登录，但 sudo 无法免密码。
证书认证本身不依赖 agent，只依赖 `~/.ssh/my-key-cert.pub` 文件。

### 9.6 其他 API 端点

```bash
# 查看 CA 版本信息
curl -sk https://ca-server:8443/api/version
# {"version":"2.3.0"}

# 查看组信息（需 mTLS）
curl -sk --cert client.cert --key client.key \
  https://ca-server:8443/api/info?level=full

# 查看 CA 公钥
curl -sk https://ca-server:8443/api/info
# {"ca_fingerprint":"SHA256:xxx","groups":{...}}
```

### 9.7 手动部署 sudo wrapper

当无法使用 `deploy-sudo-wrapper.sh` 时（如没有脚本文件），可以在目标服务器上手动操作。

```bash
# 在目标服务器上（以 root 执行）：

# 1. dpkg-divert：把真 sudo 移到 _sudo
dpkg-divert --divert /usr/bin/_sudo --rename /usr/bin/sudo

# 2. 写 wrapper 脚本
cat > /usr/bin/sudo << 'WRAPPER'
#!/bin/bash
# 先把 SSH_AUTH_SOCK 写入文件供 PAM 使用
echo "${SSH_AUTH_SOCK:-}" > /tmp/.cert-sudo-sock

_REAL_SUDO=/usr/bin/_sudo
_CERT_CHECK=/usr/local/bin/cert-sudo-check

_HAS_N=0
_N_ARGS=()
for _A in "$@"; do
    case "$_A" in
        -n) _HAS_N=1 ;;
        -n*) echo "sudo: -n 不能与其他参数组合" >&2; exit 1 ;;
        *) _N_ARGS+=("$_A") ;;
    esac
done

if [ "$_HAS_N" = "1" ]; then
    if [ -x "$_CERT_CHECK" ] && "$_CERT_CHECK"; then
        exec "$_REAL_SUDO" "${_N_ARGS[@]}"
    fi
    echo >&2 "sudo: need password"
    exit 1
fi
exec "$_REAL_SUDO" "$@"
WRAPPER
chmod 755 /usr/bin/sudo

# 3. 安装 cert-sudo-check
cat > /usr/local/bin/cert-sudo-check << 'CHECK'
#!/bin/bash
set -u
CA_PUB_FILE="${CERT_SUDO_CA:-/opt/ca_server/data/ca_key.pub}"
SUDO_EXT="${CERT_SUDO_EXT:-sudo@cert-operator}"

get_ca_fp() {
    [ -f "$CA_PUB_FILE" ] || return 1
    ssh-keygen -lf "$CA_PUB_FILE" 2>/dev/null | awk '{print $2}'
}

check_sock() {
    local sock="$1" ca_fp="$2" data line tmp
    [ ! -S "$sock" ] && return 1
    data=$(SSH_AUTH_SOCK="$sock" ssh-add -L 2>/dev/null) || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        [ -z "$line" ] && continue
        echo "$line" | grep -q "cert-v01@openssh.com" || continue
        tmp=$(mktemp) || continue
        echo "$line" > "$tmp"
        info=$(ssh-keygen -L -f "$tmp" 2>/dev/null)
        rm -f "$tmp"
        [ -z "$info" ] && continue
        echo "$info" | grep -q "$ca_fp" || continue
        echo "$info" | grep -q "$SUDO_EXT" && return 0
    done <<< "$data"
    return 1
}

CA_FP=$(get_ca_fp) || exit 1
SOCK="${SSH_AUTH_SOCK:-}"
if [ -z "$SOCK" ] || [ ! -S "$SOCK" ]; then
    [ -f /tmp/.cert-sudo-sock ] && SOCK=$(cat /tmp/.cert-sudo-sock 2>/dev/null)
fi
[ -z "$SOCK" ] || [ ! -S "$SOCK" ] && exit 1
check_sock "$SOCK" "$CA_FP" && exit 0
exit 1
CHECK
chmod +x /usr/local/bin/cert-sudo-check

# 4. 配置 PAM
cat >> /etc/pam.d/sudo << 'PAM'
# cert-operator
auth sufficient pam_exec.so /usr/local/bin/cert-sudo-check
PAM

# 5. 配置 CA 公钥
mkdir -p /opt/ca_server/data
# 从 CA 服务器获取 ca_key.pub 放到此目录

# 6. 配置 SSH 信任
cp /opt/ca_server/data/ca_key.pub /etc/ssh/ca_key.pub
echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config
systemctl restart sshd
```

### 9.8 手动卸载

```bash
# 以 root 执行：

# 1. 删除 wrapper
rm -f /usr/bin/sudo

# 2. 从 dpkg-divert 恢复原 sudo
dpkg-divert --rename --remove /usr/bin/sudo 2>/dev/null || true
# 如果 _sudo 还在但 dpkg-divert 已不在
[ ! -f /usr/bin/sudo ] && [ -f /usr/bin/_sudo ] && mv /usr/bin/_sudo /usr/bin/sudo

# 3. 删除 cert-sudo-check
rm -f /usr/local/bin/cert-sudo-check

# 4. 清理 PAM
sed -i '/cert-operator/d;/cert-sudo-check/d' /etc/pam.d/sudo

# 5. 清理临时文件
rm -f /tmp/.cert-sudo-sock /etc/sudoers.d/99-cert-operator

# 6. 验证
/usr/bin/sudo --version

# 如果 sudo 丢了：
# apt reinstall -y sudo
```

### 9.9 常见手工操作错误

| 错误 | 原因 | 解决 |
|------|------|------|
| `curl: (60) SSL certificate problem` | CA 使用自签证书，缺 `-k` | 加 `-sk` 或传 `--cacert` |
| `curl: (58) unable to set ...` | 客户端证书路径不对 | 检查 `--cert` `--key` 参数 |
| `ssh: no key algorithm provided` | SSH 版本不支持证书 | 升级 OpenSSH |
| `jq: command not found` | 未安装 jq | 手动提取 JSON 字段 |
| `sed: -i may not be used with stdin` | macOS 上 sed 语法不同 | 用 `sed -i ''` 或直接用文本编辑器 |

## 附录 A：快速诊断脚本

```bash
#!/bin/bash
# cert-operator 诊断：检查环境是否正常工作

echo "=== 客户端 ==="
which cert-operator && cert-operator version
ls ~/.hermes/certs/ 2>/dev/null || echo "无证书目录"
echo ""

echo "=== SSH Agent ==="
echo "SSH_AUTH_SOCK=${SSH_AUTH_SOCK:-未设置}"
ssh-add -l 2>/dev/null || echo "agent 中无证书"
echo ""

echo "=== 远程服务器诊断 ==="
REMOTE=$1
PORT=${2:-22}
USER=${3:-root}
if [ -n "$REMOTE" ]; then
    ssh -A -o ConnectTimeout=5 $USER@$REMOTE -p $PORT "
        echo '--- sudo wrapper ---'
        file /usr/bin/sudo
        echo '--- cert-sudo-check ---'
        ls -la /usr/local/bin/cert-sudo-check 2>/dev/null || echo '未安装'
        echo '--- PAM ---'
        grep cert-sudo-check /etc/pam.d/sudo 2>/dev/null || echo '未配置'
        echo '--- CA ---'
        ssh-keygen -lf /opt/ca_server/data/ca_key.pub 2>/dev/null || echo 'CA 公钥未找到'
        echo '--- SSH 信任 ---'
        grep TrustedUserCAKeys /etc/ssh/sshd_config
    "
fi
```

用法：
```bash
bash diagnose.sh 121.196.206.66 22 root
```

## 附录 B：版本对应关系

| 组件 | 当前版本 | 说明 |
|------|---------|------|
| `cert-operator` CLI | v2.3.0 | 客户端命令行工具 |
| `ca-server` | v2.3.0 | 服务器端 |
| `cert-operator-plugin` | v2.3.0 | Hermes AI 插件 |
| `cert-sudo-check` | v9 | 目标服务器 PAM 检查脚本 |
| `sudo-wrapper` | v2 | 目标服务器 sudo 替换脚本 |
| `deploy-sudo-wrapper.sh` | v2 | 目标服务器部署脚本 |

**版本一致性要求：** 所有组件版本号必须一致。不匹配可能导致接口不兼容。

## 附录 C：文件清单

### 客户端（开发机）

```
~/.hermes/certs/
├── ca-https-cert.pem          # CA 服务器的 HTTPS 证书（自签）
├── client.cert                # mTLS 客户端证书
├── client.key                 # mTLS 客户端私钥
├── web-server                 # SSH 私钥（get_sub_cert 获取）
├── web-server-cert.pub       # SSH 证书（get_sub_cert 获取）
├── db-backup                  # 另一个私钥（同一 CA 签发）
└── db-backup-cert.pub        # 另一个证书
```

### 目标服务器

```
/usr/bin/
├── sudo                   # wrapper 脚本（替换了原 sudo）
└── _sudo                  # 原 sudo 二进制（setuid 4755）

/usr/local/bin/
└── cert-sudo-check        # PAM 检查脚本

/opt/ca_server/data/
└── ca_key.pub             # CA 公钥

/etc/
├── pam.d/
│   └── sudo               # PAM 配置（包含 pam_exec.so cert-sudo-check）
├── ssh/
│   └── ca_key.pub         # SSH TrustedUserCAKeys
└── sudoers.d/
    └── 99-cert-operator   # env_keep SSH_AUTH_SOCK（可选）
```

---

> **给 AI 的最后提示：** 当 `ssh_with_cert` 失败时，不要反复重试同样的参数。
> 先在远程服务器上跑一下诊断脚本定位根因，再针对性修复。
> 最常见的三个失败原因：证书过期、缺少 `-A`、sudo wrapper 未部署。
