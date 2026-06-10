# 安全模型

## 认证层

### 第一层：TOTP（双因素认证）

用户从手机上的 TOTP App（如 Google Authenticator）获取当前 6 位一次性验证码。没有这验证码，即使有客户端证书也无法获取 SSH 子证书。

- 每个组有独立的 TOTP 密钥
- 服务器限速：默认 5 次尝试 / 5 分钟 / IP
- 6 位 TOTP 有 1,000,000 种组合，暴力破解需约 694 天

### 第二层：mTLS（传输层加密）

HTTPS 双向证书验证：

- 服务端验证：客户端持有 CA 签发的 mTLS 客户端证书
- 客户端验证：服务端持有 CA 签发的 HTTPS 证书
- 默认启用，可通过 `--no-mtls` 禁用（不推荐）

### 第三层：SSH CA 签名

CA 服务器的 SSH 私钥对用户的临时公钥进行签名，生成 SSH 子证书：

- 子证书有固定有效期（默认 60 分钟）
- 子证书包含允许登录的用户名（Principal）
- 目标服务器通过 TrustedUserCAKeys 验证签名

## 权限控制

### 用户组

每个组配置独立的：

- **Allowed users** — 允许获取该组证书的 SSH 用户名
- **TOTP secret** — 该组的 TOTP 密钥
- **Validity** — 该组证书的有效期
- **sudo** — 证书是否包含 `sudo@cert-operator` 扩展
- **frozen** — 停止该组签发证书

### sudo 权限控制

目标服务器上的 `cert-sudo-check` PAM 模块实现 sudo 权限控制：

- 含 `sudo@cert-operator` 扩展的证书 → sudo 免密码
- 不含该扩展的证书 → 降级到密码
- 无证书（仅密码登录）→ 降级到密码

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

- CA 服务器以 `cert-operator` 系统用户（无登录 shell）运行
- 二进制权限 `750`（owner root，group cert-operator）
- 管理命令通过 `sudo -u cert-operator` 执行

## 已知限制

- `cert-sudo-check` 需要 SSH agent forwarding（`ssh -A`）才能实现 sudo 免密码
- 无 agent forwarding 时降级到密码（安全回退）
- CA 私钥在文件系统中，建议在正式环境加密存储或使用 HSM
