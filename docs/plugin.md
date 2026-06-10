# Hermes 插件

## 概述

`cert-operator-plugin` 是为 [Hermes AI](https://hermesagent.org.cn) 设计的插件，让 AI 能够通过 TOTP + 证书认证方式安全 SSH 到目标服务器。

插件提供两个工具：

| 工具 | 描述 |
|------|------|
| 🔐 `get_sub_cert` | 工作流第 1 步：获取 TOTP → CA 签发 SSH 证书 → 保存本地 |
| 🔑 `ssh_with_cert` | 工作流第 2 步：用证书 SSH 登录目标服务器 |

## 安装

```bash
mkdir -p ~/.hermes/plugins/cert-operator

# 下载插件
wget https://github.com/user/cert-operator/releases/download/v2.0.0/cert-operator-plugin-v2.0.0.tar.gz
tar -xzf cert-operator-plugin-v2.0.0.tar.gz -C ~/.hermes/plugins/cert-operator

# 部署客户端证书
# 从 CA 服务器复制 deploy.sh 并运行
scp user@ca-server:/opt/ca_server/data/dist/deploy.sh .
bash deploy.sh
```

重启 Hermes 后，工具自动出现在工具列表中。

## 工具说明

### get_sub_cert

获取 SSH 子证书。AI 的使用流程：

1. AI 判断用户需要 SSH 到某台服务器
2. AI 告诉用户：请打开 TOTP 认证器 App，告诉我当前验证码
3. 用户提供 6 位验证码
4. AI 调用 `get_sub_cert`

**参数：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `server` | ✅ | CA 服务器地址 |
| `totp_code` | ✅ | 用户提供的 6 位 TOTP 码 |
| `cert_name` | ✅ | 证书标识（本地文件名） |
| `ca_cert_path` | | CA HTTPS 证书（默认 `~/.hermes/certs/ca-https-cert.pem`） |
| `client_cert` | | mTLS 证书（默认 `~/.hermes/certs/client.cert`） |
| `client_key` | | mTLS 密钥（默认 `~/.hermes/certs/client.key`） |
| `group_name` | | 用户组名，决定 sudo 权限 |
| `user_name` | | SSH 用户名 |

**返回示例：**

```json
{
  "success": true,
  "cert_path": "/home/user/.hermes/certs/prod-server",
  "cert_name": "prod-server",
  "serial": "42",
  "expires_at": "2026-06-10T12:00:00Z"
}
```

### ssh_with_cert

用 SSH 子证书连接目标服务器并执行命令。

**参数：**

| 参数 | 必填 | 说明 |
|------|------|------|
| `host` | ✅ | 目标服务器 IP 或主机名 |
| `user` | ✅ | SSH 用户名 |
| `cert_path` | ✅ | get_sub_cert 返回的 cert_path |
| `command` | | 要执行的命令（省略则生成 SSH 命令字符串） |
| `port` | | SSH 端口（默认 22） |

## 工作流示例

```
用户: 帮我看看 web 服务器的磁盘使用情况
AI:    好的，我需要先获取 SSH 证书。
       请打开你的 TOTP 认证器 App，告诉我当前的验证码。
用户: 验证码是 482901
AI:    [调用 get_sub_cert(server=..., totp_code=482901, ...)]
       证书已获取，现在连接服务器检查...
       [调用 ssh_with_cert(host=..., command="df -h", ...)]
       web 服务器的磁盘情况：
       /dev/sda1  50G  20G  30G  40%
       ...
```

## 兼容性

插件兼容 v1 (Python) 和 v2 (Go) CA 服务器。
HTTP 请求优先使用 `requests` 库，回退到 Python 标准库 `urllib`。

## 安全

- TOTP 码仅短暂经过 AI 上下文，不在磁盘持久化
- 私钥通过 HTTPS 加密传输，保存时权限 600
- AI 只看到证书文件路径，看不到私钥内容
- 使用 `_safe_filename` 防止路径遍历攻击
