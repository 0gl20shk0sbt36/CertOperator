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
```
