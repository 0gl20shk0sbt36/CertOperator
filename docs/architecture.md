# 架构说明

## 整体架构

```
┌─────────────────┐     HTTPS + mTLS      ┌──────────────────┐
│  用户 / TOTP App │◀────── TOTP ────────▶│  CA 服务器        │
│  (Google Auth)   │                       │  (端口 8443)      │
└─────────────────┘                       │  ca-server 二进制  │
        │                                 └────────┬─────────┘
        │ 6 位验证码                                 │ SSH 子证书
        ▼                                           ▼
┌─────────────────┐                       ┌──────────────────┐
│  Hermes AI       │                       │  目标服务器       │
│  (cert-operator  │──── SSH 证书 ────────▶│  (SSHD + PAM)     │
│   插件)          │                       │   cert-sudo-check │
└─────────────────┘                       └──────────────────┘
```

## 认证层序

1. **TOTP (应用层)** — 用户从手机 Authenticator App 获取 6 位一次性码
2. **mTLS (传输层)** — HTTPS 双向证书验证，客户端和服务端互相验证
3. **SSH CA 签名** — CA 服务器用私钥为用户的临时公钥签名，生成 SSH 子证书
4. **目标服务器验证** — 目标服务器通过 TrustedUserCAKeys 验证证书签名
5. **sudo 权限控制** — 证书中的 sudo 扩展决定用户能否 sudo

## 组件关系

### CA 服务器 (ca-server)

```
ca-server
  ├── init             首次初始化（生成 CA 密钥、HTTPS 证书、客户端证书）
  ├── serve            启动 HTTPS API 服务（mTLS / --no-mtls）
  ├── groups           用户组管理（创建、删除、配置、继承）
  ├── totp             TOTP 配置
  ├── pubkey           显示 CA 公钥
  ├── renew-cert       重新生成 HTTPS 证书（更新 SAN）
  └── version          版本信息
```

### 客户端 (cert-operator)

```
cert-operator
  ├── get-cert         从 CA 服务器获取 SSH 子证书
  ├── ssh              用子证书 SSH 登录目标服务器
  ├── deploy           部署客户端证书
  └── version          版本信息
```

### Hermes 插件 (cert-operator-plugin)

插件为 Hermes AI 提供两个工具，按顺序调用来完成 SSH 登录：

1. **get_sub_cert** — AI 向用户索取 TOTP → 调 CA API → 获取证书
2. **ssh_with_cert** — 用证书 SSH 登录 → 执行命令 → 返回结果

## 数据流

```
get_sub_cert 请求:
  POST /api/get-cert
  Body:  {"totp": "123456", "group": "admin", "user": "root"}
  Response:
  {
    "success": true,
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----...",
    "ssh_cert": "ssh-ed25519-cert-v01@openssh.com...",
    "serial": 42,
    "expires_at": "2026-06-10T12:00:00Z"
  }
```
