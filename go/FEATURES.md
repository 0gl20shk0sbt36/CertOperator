# cert-operator v1.2.0 功能清单 → v2.0.0 Go 重写对照

## 服务端 (ca_server.py → go/ca-server)

| # | Python 功能 | 状态 |
|---|-----------|------|
| 1 | `init` — 生成 CA 密钥、HTTPS 证书、mTLS 客户端证书、deploy.sh | ☐ |
| 2 | `serve` — 启动 mTLS HTTPS 服务 (CERT_REQUIRED) | ☐ |
| 3 | `serve --no-mtls` — 禁用 mTLS | ☐ |
| 4 | `serve --debug` — 调试模式 | ☐ |
| 5 | `serve --host/--port` — 覆盖配置 | ☐ |
| 6 | `pubkey` — 显示 CA 公钥 | ☐ |
| 7 | `totp` — 配置/查看 default 组 TOTP | ☐ |
| 8 | `totp --verify` — 验证 TOTP | ☐ |
| 9 | `totp --regenerate` — 重新生成 Secret | ☐ |
| 10 | `renew-cert` — 重新生成 HTTPS 证书 | ☐ |
| 11 | `groups create/delete/list` | ☐ |
| 12 | `groups users add/remove/list` | ☐ |
| 13 | `groups totp set/verify` | ☐ |
| 14 | `groups config get/set` (sudo, frozen, parent, validity-minutes, allowed-users) | ☐ |
| 15 | 组层级继承 (allowed_users 合并, extensions 合并) | ☐ |
| 16 | 组冻结 (--frozen yes) | ☐ |
| 17 | sudo 扩展 (extension:sudo@cert-operator) | ☐ |
| 18 | 配置热重载 (实时从 config.yaml 读取) | ☐ |

## API 端点

| # | 端点 | 方法 | 状态 |
|---|------|------|------|
| 19 | /api/get-cert | POST | ☐ |
| 20 | /api/health | GET | ☐ |
| 21 | /api/info?level=basic|full | GET | ☐ |
| 22 | /api/version | GET | ☐ |

## 安全

| # | 功能 | 状态 |
|---|------|------|
| 23 | TOTP 速率限制 (5次/300秒/IP) | ☐ |
| 24 | mTLS CERT_REQUIRED | ☐ |
| 25 | cert_name 路径遍历防护 | ☐ |

## 辅助工具

| # | 功能 | 状态 |
|---|------|------|
| 26 | cert-sudo-check v2 (扫描 /tmp/ssh-*/agent.*) | ☐ |
| 27 | deploy.sh 生成（客户端证书部署脚本） | ☐ |

## 客户端 CLI (cert-operator/)

| # | 功能 | 状态 |
|---|------|------|
| C1 | `get-cert` — TOTP + mTLS 获取 SSH 子证书 | ☐ |
| C2 | `ssh` — SSH 证书登录 | ☐ |
| C3 | `deploy` — 部署客户端证书 | ☐ |
| C4 | `version` — 显示版本号 | ☐ |

## 安装/部署

| # | 功能 | 状态 |
|---|------|------|
| D1 | install.sh 自解压安装 | 仅 v1 |
| D2 | uninstall.sh 卸载 | 仅 v1 |
| D3 | systemd 服务 | 仅 v1 |
| D4 | 回滚机制 | 仅 v1 |
| D5 | 依赖检查 | 仅 v1 |

Go 版本优势：单二进制部署，无需 install.sh/uninstall.sh/systemd 集成
