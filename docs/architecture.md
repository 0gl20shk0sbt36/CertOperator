# 架构说明

## 整体架构

```
┌─────────────────┐    HTTPS + mTLS     ┌──────────────────┐    SSH 证书      ┌──────────────────┐
│  用户/TOTP App  │────── TOTP ────────▶│  CA 服务器        │───────────────▶│  目标服务器       │
│  (Authenticator)│◀──── SSH 证书 ──────│  (端口 8443)      │                │  (SSHD + PAM)     │
└─────────────────┘                     │  ca-server 二进制  │                │  cert-sudo-check  │
                                        └──────────────────┘                │  sudo-wrapper     │
                                                                            └──────────────────┘
```

认证栈从底向上：

```
┌── sudo 权限层 ──────────────────────────────────────────┐
│  sudo-wrapper（dpkg-divert 替换 /usr/bin/sudo）            │
│  + PAM cert-sudo-check（pam_exec.so）                      │
│  证书有 sudo@cert-operator 扩展 → 免密码 sudo ✅            │
│  无扩展 / 无证书 → 降级到密码 / 拒绝                        │
├── SSH 证书层 ────────────────────────────────────────────┤
│  SSH CA 签名证书，TrustedUserCAKeys 验证                    │
│  证书包含 principal（用户名）、serial、有效期、扩展          │
├── 传输层 ────────────────────────────────────────────────┤
│  HTTPS + mTLS（双向 TLS 验证，默认开启）                    │
│  服务端出示 https_cert.pem，客户端出示 client.cert          │
│  TLS 1.2+ 加密，默认 8443 端口                             │
└── 应用层 ────────────────────────────────────────────────┘
  TOTP（6 位一次性码，30 秒窗口，防止重放攻击）
```

## 认证流程

### 获取证书（get_sub_cert）

```
用户              Hermes AI / CLI        CA 服务器
 │                     │                     │
 │ 1. 打开 TOTP App    │                     │
 │ 2. 告诉 AI 验证码   │                     │
 │────────────────────▶│                     │
 │                     │ 3. POST /api/get-cert│
 │                     │    {totp, group}    │
 │                     │────────────────────▶│
 │                     │                     │ 4. 验证 TOTP
 │                     │                     │ 5. 生成临时密钥对
 │                     │                     │ 6. CA 签名 → SSH 证书
 │                     │◀────────────────────│
 │                     │ 7. 保存私钥+证书     │
 │                     │ 8. cert_path 返回    │
```

### 权限验证（sudo -n）

```
客户端（cert-operator ssh -A）        目标服务器
 │                                       │
 │ 1. ssh-agent 启动                     │
 │ 2. ssh-add 加载证书                    │
 │ 3. SSH -A（agent 转发）               │
 │──────────────────────────────────────▶│
 │                                       │ 4. TrustedUserCAKeys 验证
 │                                       │    SSH 认证通过 ✅
 │                                       │
 │                    sudo -n whoami     │
 │                       ↓               │
 │                   /usr/bin/sudo       │
 │                   （wrapper 脚本）      │
 │                       ↓               │
 │                   写 SSH_AUTH_SOCK     │
 │                   到 /tmp/.cert-sudo-  │
 │                   sock                │
 │                       ↓               │
 │                   调 cert-sudo-check   │
 │◀──── agent 查询 ────│                 │
 │ 证书有 sudo 扩展？   │                 │
 │──── yes ──────────▶│                 │
 │                       ↓               │
 │                   exec /usr/bin/_sudo │
 │                   whoami（去掉 -n）    │
 │                       ↓               │
 │                   PAM → cert-sudo-    │
 │                   check 读 sock 文件   │
 │                   二次确认 → 放行       │
 │                       ↓               │
 │                   root ✅             │
```

## 组件详解

### CA 服务器（ca-server）

Go 编译的单二进制，零外部依赖。

```
ca-server
  ├── init           首次初始化（CA密钥 + HTTPS证书 + 客户端证书）
  ├── serve          启动 HTTPS API 服务（默认 8443）
  ├── pubkey         显示 CA 公钥
  ├── totp           TOTP 管理
  ├── groups         组管理（create/delete/users/totp/config）
  ├── renew-cert     重新生成 HTTPS 证书（--san 更新 SAN）
  ├── reset          组件重置（ca/https/client/totp/group/all）
  └── version        版本信息
```

### 客户端 CLI（cert-operator）

```
cert-operator
  ├── get-cert       从 CA 获取 SSH 证书
  ├── ssh            用证书 SSH 登录（自动 + agent + -A 转发）
  ├── deploy         部署客户端证书（很少用）
  └── version        版本信息
```

SSH 子命令自动处理：
1. 启动 ssh-agent（每次新进程）
2. 加载证书 → ssh-add
3. SSH -A 连接（agent 转发供远程验证）
4. 命令结束后杀死 agent

### sudo-wrapper（目标服务器）

通过 `dpkg-divert` 替换 `/usr/bin/sudo`：

```
部署前: /usr/bin/sudo          ← 真 sudo（setuid root）
部署后: /usr/bin/_sudo         ← 真 sudo（setuid root）
       /usr/bin/sudo          ← wrapper 脚本（普通权限）
```

wrapper 行为：
- 收到 `sudo -n xxx` → 调 cert-sudo-check 验证 → 通过 → exec `_sudo xxx`（去 -n）
- 收到 `sudo xxx`（无 -n）→ 直接转发 `_sudo xxx`
- 写 `$SSH_AUTH_SOCK` 到 `/tmp/.cert-sudo-sock`（供 PAM 读取）

### cert-sudo-check v9（目标服务器）

验证逻辑：

```
1. 读 $SSH_AUTH_SOCK（wrapper 调用时有）→  连 agent 查证书 → 有 sudo 扩展？✅
2. 读 /tmp/.cert-sudo-sock（PAM 调用时）  →  连 agent 查证书 → 有 sudo 扩展？✅
3. 都失败 → exit 1（拒绝 sudo）
```

依赖：SSH agent forwarding（`ssh -A`）。不依赖 `/proc` 进程树遍历。

### Hermes 插件

见 [插件手册](../cert-operator-plugin/USAGE.md)。

## 数据流示例

### 获取证书

```
POST /api/get-cert
Headers: Content-Type: application/json
Body:    {"totp":"123456","group":"admin","user":"root"}

Response:
{
  "success": true,
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----...",
  "ssh_cert": "ssh-ed25519-cert-v01@openssh.com...",
  "serial": 42,
  "expires_at": "2026-06-10T12:00:00Z"
}
```

### 证书内容

```
ssh-keygen -L -f user-cert.pub

/TMP/user-cert.pub:
  Type: ssh-ed25519-cert-v01@openssh.com
  Signing CA: ED25519 SHA256:xxx (CA 指纹)
  Key ID: "cert-42"
  Serial: 42
  Valid: from now to +60min
  Principals: root
  Extensions:
    permit-X11-forwarding
    permit-agent-forwarding
    permit-port-forwarding
    permit-pty
    permit-user-rc
    sudo@cert-operator                      ← sudo 权限
```
