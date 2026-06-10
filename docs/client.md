# 客户端使用

## 获取证书

```bash
# 基本用法
cert-operator get-cert <server> <totp_code> <cert_name>

# 示例
cert-operator get-cert https://192.168.1.100:8443 123456 my-server

# 指定组和用户
cert-operator get-cert https://192.168.1.100:8443 123456 prod-db \
  --group admin \
  --user root
```

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `server` | ✅ | CA 服务器地址，`https://IP:8443` |
| `totp_code` | ✅ | 用户从 TOTP App 看的 6 位码 |
| `cert_name` | ✅ | 证书标识，用于本地文件名 |
| `--group` | | 用户组名，控制 sudo/有效期 |
| `--user` | | SSH 用户名 |
| `--ca-cert` | | CA HTTPS 证书路径 |
| `--client-cert` | | mTLS 客户端证书路径 |
| `--client-key` | | mTLS 客户端密钥路径 |

证书保存到 `~/.hermes/certs/<cert_name>`（私钥）和 `<cert_name>-cert.pub`（证书）。

## SSH 登录

```bash
# 基本用法
cert-operator ssh <host> <user> <cert_path>

# 示例 - 执行命令
cert-operator ssh 192.168.1.100 root ~/.hermes/certs/prod-db "uname -a"

# 示例 - 交互式连接（不传 command）
cert-operator ssh 192.168.1.100 root ~/.hermes/certs/prod-db

# 非标端口
cert-operator ssh 192.168.1.100 root ~/.hermes/certs/prod-db --port 2222
```

**参数说明：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `host` | ✅ | 目标服务器地址 |
| `user` | ✅ | SSH 用户名 |
| `cert_path` | ✅ | 私钥路径（get-cert 的返回值） |
| `command` | | 要执行的命令 |
| `--port` | | SSH 端口（默认 22） |
| `--expires-at` | | 证书过期时间，连接前检查 |

## 内部行为

`cert-operator ssh` 自动处理以下逻辑：

1. 启动新 ssh-agent（每次独立进程）
2. 用 `ssh-add` 加载证书到 agent
3. 用 `-A` 参数 SSH 连接（agent 转发供远程 cert-sudo-check 验证证书）
4. 远程 `sudo -n` 由目标服务器上的 sudo-wrapper 拦截处理
5. 命令结束后杀死 ssh-agent（无残留）

不需要用户手动管理 agent。

## Sudo 权限

远程 `sudo -n` 和 `sudo` 都支持免密码：

- 证书含 `sudo@cert-operator` 扩展 → 自动免密码
- 证书不含该扩展 → sudo 需要密码
- 无证书（仅密钥认证）→ sudo 需要密码

## 工作流示例

```bash
# 1. 获取证书
cert-operator get-cert https://ca.internal:8443 482901 prod-db \
  --group admin --user root

# ✅ 证书已保存
#    私钥: /home/user/.hermes/certs/prod-db
#    证书: /home/user/.hermes/certs/prod-db-cert.pub
#    序列号: 42

# 2. SSH 连接
cert-operator ssh prod-db.internal root /home/user/.hermes/certs/prod-db \
  "uptime && df -h"

# 3. 带 sudo
cert-operator ssh prod-db.internal root /home/user/.hermes/certs/prod-db \
  "sudo systemctl status nginx"
```

## 版本

```bash
cert-operator version
# cert-operator v3.0.0
```
