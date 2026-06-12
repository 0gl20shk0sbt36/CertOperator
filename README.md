# CertOperator

> 零信任 SSH 证书基础设施 —— 基于 TOTP + mTLS + SSH CA 的远程访问控制平台。

## 概述

CertOperator 是一个面向 Linux 基础设施的零信任远程登录方案。它用**一次性的 TOTP 验证码**替代静态 SSH 密钥，通过 **CA 签发的短生命周期证书**替代长期密钥对，并借助 **sudo wrapper + PAM** 实现精准的 sudo 权限控制。

核心思路很简单：没有永久凭据，每一次访问都需要主动申请、通过多因素认证、并且自动过期。

**特性：**
- 四层认证栈：TOTP（应用层）→ mTLS（传输层）→ SSH CA（证书层）→ sudo wrapper（权限层）
- Go 实现，零外部依赖，单一二进制部署
- 独立 mTLS 客户端证书，支持签发、续期、撤销（即时生效）
- TOTP 防重放 + 速率限制 + 审计日志
- 目标服务器无需额外 Agent，仅需 sshd + sudo wrapper + CA 公钥
- 支持组管理、权限继承、证书扩展自定义
- Hermes AI 插件，支持自然语言驱动的证书获取和 SSH 操作

## 快速开始

```bash
# 1. 服务端部署（CA 服务器）
wget https://github.com/user/cert-operator/releases/download/v3.1.1/ca-server-v3.1.1-linux-x86_64.tar.gz
tar -xzf ca-server-v3.1.1-linux-x86_64.tar.gz
cd ca-server-pack && sudo bash install.sh
cert-operator init    # 初始化 CA 密钥、HTTPS 证书、mTLS CA

# 2. 为本地客户端签发 mTLS 证书
cert-operator clients issue admin "admin" --user root
# → 生成 data/clients/admin.tar.gz

# 3. 部署客户端证书到本地
tar -xzf /opt/ca_server/data/clients/admin.tar.gz -C ~/.hermes/certs/

# 4. 配置 TOTP 和用户组
cert-operator groups create admin
cert-operator groups users admin add root
cert-operator groups totp admin set    # 扫码绑定 TOTP App
systemctl start cert-operator

# 5. 获取 SSH 证书并登录
cert-operator get-cert https://localhost:8443 123456 my-key --group admin
cert-operator ssh 192.168.1.100 root ~/.hermes/certs/my-key "sudo systemctl status nginx"
```

## 架构

```
          TOTP App (6-digit)
               │
               ▼
┌──────────────────────────────────────┐
│          CA Server                   │
│  ┌──────────────────────────────┐   │
│  │ mTLS CA → 按客户端签发独立证书│   │
│  │ TOTP 验证 + 签发 SSH 子证书   │   │
│  │ API: POST /api/get-cert     │   │
│  └──────────────────────────────┘   │
│  clients.json (mTLS 名单管理)        │
│  cert-audit.log (审计日志)           │
└──────────────┬───────────────────────┘
               │ SSH cert
               ▼
┌──────────────────────────────────────┐
│          Target Server               │
│  ┌──────────────────────────────┐   │
│  │ sshd: TrustedUserCAKeys      │   │
│  │ sudo-wrapper (dpkg-divert)   │   │
│  │ cert-sudo-check (PAM)        │   │
│  └──────────────────────────────┘   │
└──────────────────────────────────────┘
```

认证栈：**TOTP（应用层）→ HTTPS/mTLS（传输层）→ SSH CA（证书层）→ PAM + sudo wrapper（权限层）**

## 组件

| 组件 | 语言 | 功能 | 部署位置 |
|------|------|------|---------|
| **ca-server** | Go（零依赖） | CA 服务器：TOTP 验证、mTLS 证书签发、SSH 证书签发、审计 | CA 服务器 |
| **cert-operator** | Go（零依赖） | 客户端 CLI：获取 SSH 证书、deploy mTLS 证书包、SSH 连接 | 开发机 |
| **cert-operator-plugin** | Python | Hermes AI 插件：AI 驱动的证书获取和 SSH | Hermes 插件目录 |
| **cert-sudo-check** | Bash | PAM 模块：验证证书是否有 sudo 权限 | 目标服务器 |
| **sudo-wrapper** | Bash | 替换 `/usr/bin/sudo`，拦截 `sudo -n` | 目标服务器 |

## 文档

- [架构说明](docs/architecture.md) — 系统架构和认证流
- [安装指南](docs/installation.md) — 部署和卸载
- [服务端管理](docs/server-manual.md) — 所有 ca-server 命令详解
- [客户端使用](docs/client.md) — CLI 命令参考
- [插件手册](cert-operator-plugin/USAGE.md) — Hermes AI 插件使用
- [配置参考](docs/configuration.md) — config.json 配置项
- [安全模型](docs/security.md) — 安全机制和已知限制
- [维护手册](docs/maintenance.md) — 日常维护、故障排查、备份恢复
- [版本历史](.codewhale/instructions.md) — 每个版本的变更

## 版本

当前版本：**v3.1.1**

| 版本 | 变更 |
|------|------|
| v3.1.1 | TOTP 防重放漏洞修复 + 审计日志 |
| v3.1.0 | 独立 mTLS 客户端证书（mTLS CA + clients.json 管理）|
| v3.0.0 | dpkg-divert sudo wrapper、cert-sudo-check v9、agent 自动清理 |
| v2.2.0 | reset 命令、mount namespace sudo 包装 |
| v2.1.0 | cert-sudo-check v3、handler dict 修复 |
| v2.0.0 | Go 重写（零外部依赖）|

## 许可证

MIT — 详见 [LICENSE](LICENSE)。
