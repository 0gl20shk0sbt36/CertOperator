# 安全模型

## 认证层

### 第一层：TOTP（双因素认证）

用户从手机上的 TOTP App（如 Google Authenticator）获取当前 6 位一次性验证码。没有这验证码，即使有客户端证书也无法获取 SSH 子证书。

- 每个组有独立的 TOTP 密钥
- 服务器限速：默认 5 次尝试 / 5 分钟 / IP
- 6 位 TOTP 有 1,000,000 种组合，暴力破解需约 694 天

### 第二层：mTLS（传输层加密）

HTTPS 双向证书验证：

- 服务端验证：客户端持有 CA 签发的 mTLS 客户端证书（默认开启）
- 客户端验证：服务端持有 CA 签发的 HTTPS 证书
- TLS 1.2+ 加密传输
- 可通过 `--no-mtls` 禁用（**不推荐**）

### 第三层：SSH CA 签名

CA 服务器的 SSH 私钥对用户的临时公钥进行签名，生成 SSH 子证书：

- 子证书有固定有效期（默认 60 分钟）
- 子证书包含允许登录的用户名（Principal）
- 目标服务器通过 TrustedUserCAKeys 验证签名
- 证书包含扩展字段控制权限（如 `sudo@cert-operator`）

## 权限控制

### 用户组

每个组配置独立的：

- **Allowed users** — 允许获取该组证书的 SSH 用户名
- **TOTP secret** — 该组的 TOTP 密钥
- **Validity** — 该组证书的有效期
- **Extensions** — `sudo@cert-operator` 等 SSH 证书扩展
- **Frozen** — 停止该组签发证书

### sudo 权限控制

目标服务器上的两层机制实现 sudo 权限控制：

1. **sudo-wrapper**（dpkg-divert 替换 `/usr/bin/sudo`）：
   - 拦截所有 sudo 调用（包括 `/usr/bin/sudo` 绝对路径）
   - `sudo -n` 时先调 cert-sudo-check 验证，通过后转发到真 sudo（去 -n 触发 PAM）
   - 写 `$SSH_AUTH_SOCK` 到 `/tmp/.cert-sudo-sock` 供 PAM 路径使用

2. **cert-sudo-check**（PAM `pam_exec.so`）：
   - 有 agent 转发 → 读 `$SSH_AUTH_SOCK` 查证书 → 有 sudo 扩展 → 免密码 ✅
   - 无 agent 转发 → 读 `/tmp/.cert-sudo-sock` 查证书 → 有 sudo 扩展 → 免密码 ✅
   - 都不行 → exit 1（拒绝 sudo / 降级到密码）

### 组层级继承

支持多级继承：
- `allowed_users`：父子组用户合并（并集）
- `extensions`：子组覆盖父组
- 其他配置项：子组覆盖父组

## 密钥保护

| 密钥 | 位置 | 权限 | Owner |
|------|------|------|-------|
| CA 私钥 | `/opt/ca_server/data/ca_key` | `600` | cert-operator |
| HTTPS 私钥 | `/opt/ca_server/data/https_key.pem` | `600` | cert-operator |
| mTLS 客户端私钥 | `/opt/ca_server/data/client.key` | `600` | cert-operator |
| CA 公钥 | `/etc/ssh/ca_key.pub` | `644` | root |
| SSH 私钥（用户） | `~/.hermes/certs/<name>` | `600` | 用户 |
| SSH 证书（用户） | `~/.hermes/certs/<name>-cert.pub` | `644` | 用户 |

- CA 服务器以 `cert-operator` 系统用户（无登录 shell）运行
- 二进制权限 `750`（owner root，group cert-operator）
- 管理命令通过 `sudo -u cert-operator` 或 `cert-operator` 快捷命令执行

## sudo-wrapper 部署安全

dpkg-divert 机制：

- `dpkg-divert` 将真 sudo 移到 `/usr/bin/_sudo`
- `wrapper` 脚本（无 setuid）占原位置
- sudo 包升级时 dpkg 将新二进制写入 `_sudo`，不影响 wrapper
- 卸载时 `dpkg-divert --remove` 恢复真 sudo

## 已知限制

- `cert-sudo-check` 需要 SSH agent forwarding（`ssh -A`）才能验证证书
- 无 agent 转发时 `sudo -n` 会被 wrapper 拒绝（输出 needpassword）
- CA 私钥在文件系统中，建议在正式环境加密存储或使用 HSM
- `/tmp/.cert-sudo-sock` 文件可被同服务器的其他用户读取，但 socket 本身只能由 socket 拥有者访问
