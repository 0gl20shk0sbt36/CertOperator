# cert-operator

> TOTP + mTLS 双层认证 SSH 证书签发系统。基于 SSH CA 的零信任远程登录方案。

## 快速开始

```bash
# 1. 服务端部署（CA 服务器）
wget https://github.com/user/cert-operator/releases/download/v3.0.0/ca-server-install-v3.0.0.sh
sudo bash ca-server-install-v3.0.0.sh
# install.sh 会自动检测服务器 IP、生成 CA 密钥、安装 systemd 服务

# 2. 部署客户端证书
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"

# 3. 部署目标服务器 sudo wrapper
scp /opt/ca_server/data/dist/deploy-sudo-wrapper.sh root@target:/tmp/
ssh root@target "bash /tmp/deploy-sudo-wrapper.sh"

# 4. 获取证书并登录
cert-operator get-cert https://<ca-server>:8443 123456 my-key --group admin
cert-operator ssh 192.168.1.100 root ~/.hermes/certs/my-key "sudo systemctl status nginx"
```

## 架构

```
用户/TOTP App ──(6位码)──▶ CA 服务器 ──(SSH 证书)──▶ 目标服务器
                                │                    │
                             ca_key.pub          TrustedUserCAKeys
                                                 cert-sudo-check (PAM)
                                                 sudo-wrapper (dpkg-divert)
```

认证栈：**TOTP（应用层）→ HTTPS/mTLS（传输层）→ SSH CA（证书层）→ PAM + sudo wrapper（sudo 权限层）**

## 组件

| 组件 | 语言 | 功能 | 部署位置 |
|------|------|------|---------|
| **ca-server** | Go（零依赖） | CA 服务器：TOTP 验证、证书签发、管理 | CA 服务器 |
| **cert-operator** | Go（零依赖） | 客户端 CLI：获取证书、SSH 连接 | 开发机 |
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

当前版本：**v3.0.0**

| 版本 | 变更 |
|------|------|
| v3.0.0 | dpkg-divert sudo wrapper、cert-sudo-check v9、agent 自动清理 |
| v2.2.0 | reset 命令、mount namespace sudo 包装 |
| v2.1.0 | cert-sudo-check v3、handler dict 修复 |
| v2.0.0 | Go 重写（零外部依赖）|

## 许可证

MIT
