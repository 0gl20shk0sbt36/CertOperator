# cert-operator 插件使用手册（AI 阅读）

## 插件概述

cert-operator 提供两个工具，按顺序调用即可通过 SSH 安全登录目标服务器。

### 两个工具的关系

```
get_sub_cert → 获取证书 → 保存到 ~/.hermes/certs/ → 返回 cert_path
                    ↓
ssh_with_cert → 用 cert_path SSH 登录目标服务器 → 执行命令
```

---

## 第一步：get_sub_cert（获取 SSH 证书）

### 什么时候需要调用

用户要求登录某台服务器，而该服务器使用 cert-operator CA 做 SSH 认证时。

### 执行流程

1. **告诉用户**：「请打开手机上的 TOTP 认证器 App（如 Google Authenticator），查看当前的 6 位验证码」
2. **等待用户提供** 6 位验证码
3. **调用 `get_sub_cert`**，传入以下参数：

| 参数 | 必填 | 说明 |
|------|------|------|
| `server` | ✅ | CA 服务器地址，如 `https://121.196.206.66:8443` |
| `totp_code` | ✅ | 用户提供的 6 位验证码 |
| `cert_name` | ✅ | 证书标识名（本地文件名），建议用目标含义，如 `my-server` |
| `group_name` | | 组名：`root`（root+sudo）/ `aibot-sudo`（aibot+sudo）/ `aibot-nosudo`（aibot 无 sudo） |
| `user_name` | | SSH 登录用户名，如 `root` / `aibot` |
| `ca_cert_path` | | 默认 `~/.hermes/certs/ca-https-cert.pem`，通常不需要传 |
| `client_cert` | | 默认 `~/.hermes/certs/client.cert` |
| `client_key` | | 默认 `~/.hermes/certs/client.key` |

### 返回示例

```json
{
  "success": true,
  "cert_path": "/home/yyx/.hermes/certs/my-server",
  "cert_name": "my-server",
  "serial": "3",
  "expires_at": "2026-06-10T02:54:56Z"
}
```

**关键返回值：`cert_path`** — 下一步要用。

### 常见错误

| 错误 | 原因 | 处理 |
|------|------|------|
| TOTP 验证失败 | 验证码过期或输入错误 | 请用户刷新 TOTP 重新提供 |
| 429 Too Many Requests | 频繁请求被限流 | 等待 5 分钟再试 |
| 用户 XXX 不在允许列表中 | 该组不允许此用户 | 改用其他组或联系管理员 |
| 组 XXX 不存在 | 组名不存在 | 使用 `root` / `aibot-sudo` / `aibot-nosudo` |

---

## 第二步：ssh_with_cert（用证书 SSH 登录）

### 什么时候调用

上一步 `get_sub_cert` 成功返回 `cert_path` 后。

### 参数

| 参数 | 必填 | 说明 |
|------|------|------|
| `host` | ✅ | 目标服务器 IP，如 `121.196.206.66` |
| `user` | ✅ | SSH 用户名，与 get_sub_cert 的 user_name 一致 |
| `cert_path` | ✅ | get_sub_cert 返回的 `cert_path` |
| `command` | | 要执行的命令。省略则生成 SSH 命令字符串供用户手动执行 |
| `port` | | SSH 端口，默认 22 |

### 返回示例

```json
{
  "success": true,
  "output": "root\niZbp1h9gh3owlcau5welixZ\nroot",
  "exit_code": 0
}
```

### 关于 sudo 免密码

cert-operator CLI 在 SSH 时会自动：
1. 将证书加载到 SSH agent
2. 启用 agent forwarding（`-A`）

因此远程服务器上的 `cert-sudo-check` 能读取到证书中的 `sudo@cert-operator` 扩展，
实现 sudo 免密码。无需人工操作。

---

## 完整工作流示例

```
用户: 帮我看看服务器的磁盘使用情况
AI:    好的，这台服务器使用 SSH 证书认证。请打开你的 TOTP 认证器 App，
       告诉我当前的 6 位验证码。
用户: 验证码是 482901
AI:    验证码已收到，正在获取证书...
       [调用 get_sub_cert(server="https://121.196.206.66:8443",
                          totp_code="482901",
                          cert_name="disk-check",
                          group_name="root",
                          user_name="root")]
       ✅ 证书已获取，正在连接服务器检查磁盘...
       [调用 ssh_with_cert(host="121.196.206.66",
                          user="root",
                          cert_path="/home/yyx/.hermes/certs/disk-check",
                          command="df -h")]
用户: 看到了，谢谢
```

---

## CA 服务器地址

当前部署的 CA 服务器：`https://121.196.206.66:8443`

| 组名 | 允许用户 | sudo |
|------|---------|------|
| `root` | root | ✅ |
| `aibot-sudo` | aibot | ✅ |
| `aibot-nosudo` | aibot | ❌ |

---

## 证书签名验证失败（sudo 要求密码）

### 现象

证书获取成功且未过期，SSH 连接正常，但 `sudo` 命令提示输入密码（即使该组配置了 `sudo=yes`）。

### 根因

CA 服务器的 CA 密钥对被重新生成了（`reset ca` 或 `init`），而本地仍在使用旧 CA 签发的证书。

```
时间线:
  管理员执行 reset ca → CA 密钥更换 → 旧证书全部失效
  AI 获取新证书 ✅（由新 CA 签名）
  AI 误用旧证书文件 ❌（由旧 CA 签名，仍存在磁盘上）
  cert-sudo-check 读取新 CA 公钥 → 验证证书 CA 指纹 → 不匹配 → exit 1 → 降级到密码
```

**注意：** 此问题不是代码缓存。CA 服务器不缓存任何密钥，每次签证都实时从磁盘读取 CA 私钥。旧证书物理存在于本地 `~/.hermes/certs/` 目录中，只是不再被当前 CA 认可。

### 修复

1. **清理旧证书**：删除 `~/.hermes/certs/` 中之前获取的旧证书文件
2. **重新获取证书**：重新调用 `get_sub_cert` 获取由当前 CA 签发的新证书
3. 不需要重新运行 `deploy.sh`（deploy.sh 分发的是 HTTPS 证书和 mTLS 证书，它们独立于 CA 密钥，不受影响）

### 如何判断

查看证书的签名 CA 指纹是否与服务器的一致：

```bash
# 查看本地证书的签名 CA
ssh-keygen -L -f ~/.hermes/certs/<cert_name>-cert.pub | grep 'Signing CA'

# 查看服务器当前的 CA 指纹（通过 API）
curl -sk https://121.196.206.66:8443/api/info | grep ca_public
```

---

## 安全说明

- TOTP 码仅短暂经过 AI 上下文，不在磁盘持久化
- SSH 私钥通过 HTTPS 加密传输，保存时权限 600
- AI 只看到证书文件路径，看不到私钥内容
- 证书有效期 60 分钟，过期需重新获取
