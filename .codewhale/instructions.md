# cert-operator 项目上下文（2026-06-10）

## 项目结构

```
workspace/
├── go/ca-server/                   # Go 重写 v2.x 代码
│   ├── bin/
│   │   ├── ca-server               # 服务端二进制 (4.8M)
│   │   └── cert-operator           # 客户端 CLI 二进制 (4.8M)
│   ├── cmd/
│   │   ├── ca-server/main.go       # 服务端 CLI (init/serve/groups/totp/reset/...)
│   │   └── cert-operator/main.go   # 客户端 CLI (get-cert/ssh/version)
│   ├── internal/
│   │   ├── ca/ca.go                # CA 密钥管理 + 重置函数
│   │   ├── cert/cert.go            # SSH 证书签发
│   │   ├── config/config.go        # JSON 配置加载
│   │   ├── server/server.go        # HTTPS + mTLS API 服务器
│   │   ├── totp/totp.go            # TOTP 生成/验证 (纯 Go)
│   │   └── ratelimit/ratelimit.go  # 内存限速器
│   ├── install.sh                  # 一键安装 (63行, 零外部依赖)
│   ├── uninstall.sh                # 卸载脚本
│   └── go.mod                      # 零外部依赖
│
├── cert-operator-plugin/           # Hermes 插件（Python）
│   ├── __init__.py                 # 插件入口 (396行)
│   ├── plugin.yaml                 # 插件清单
│   └── USAGE.md                    # AI 使用手册
│
├── cert-sudo-check                 # PAM sudo 检查脚本 (v3, 磁盘扫描版, 52行)
├── docs/                           # 文档
│   ├── architecture.md
│   ├── installation.md
│   ├── client.md
│   ├── plugin.md
│   ├── configuration.md
│   └── security.md
├── test/                           # Docker 测试环境
│   ├── docker-compose.yml          # docker compose 测试
│   └── docker-compose/             # Dockerfiles
├── archive/                        # v1 源码归档
│   ├── cert-operator-v1.2.0.tar.gz
│   └── cert-operator-v1-full.tar.gz
└── release/                        # 发行包
    ├── ca-server-v2.2.0-linux-x86_64.tar.gz
    ├── cert-operator-v2.2.0-linux-x86_64.tar.gz
    └── cert-operator-plugin-v2.2.0.tar.gz
```

## 版本历史

- v1.2.0 — Python 版最终版（已归档）
- v2.0.0 — Go 重写，零外部依赖
- v2.1.0 — cert-sudo-check v3 磁盘扫描 + handler dict 修复
- v2.2.0 — reset 命令 + mount namespace sudo 包装
- v3.0.0 — dpkg-divert sudo wrapper、cert-sudo-check v9、agent 自动清理
- v3.1.0 — 独立 mTLS 客户端证书（mTLS CA + 按客户端签发 + clients.json 管理）
- v3.1.1 — TOTP 防重放漏洞修复（当前版本）

## 架构

```
用户/TOTP App ──(6位码)──▶ CA 服务器 ──(SSH 证书)──▶ 目标服务器
                                │                    │
                             ca_key.pub          TrustedUserCAKeys
                                                 cert-sudo-check (PAM)
```

认证栈：TOTP（应用层）→ HTTPS（传输层）→ SSH CA（证书层）→ PAM（sudo 权限层）

## 核心问题及解决方案

### 问题：Ubuntu 24.04+ sudo -n 不调用 PAM

`sudo -n` 在检测到用户需要密码时，直接退出"sudo: needpassword"，不执行 PAM 栈。
导致 PAM 中配置的 `pam_exec.so cert-sudo-check` 永远不会运行。

**解决方案：dpkg-divert + 静态 sudo wrapper（目标服务器部署）**

在目标服务器上用 `dpkg-divert` 永久重命名原 sudo，用 wrapper 脚本替代 `/usr/bin/sudo`。

```
部署时（一次性 root）:
  dpkg-divert --divert /usr/bin/_sudo --rename /usr/bin/sudo
  # dpkg 记住真 sudo 在 _sudo，以后包更新写到 _sudo 位置
  install -m 755 sudo-wrapper /usr/bin/sudo

运行时:
  sudo -n xxx
    → /usr/bin/sudo（wrapper）截获
    → 调 cert-sudo-check 验证证书（$SSH_AUTH_SOCK 快速路径）
    → 通过：exec /usr/bin/_sudo xxx（去掉 -n，PAM 二次确认）
    → 失败：输出 needpassword

  sudo xxx
    → wrapper 原样转发给 /usr/bin/_sudo
    → PAM → cert-sudo-check（读 /tmp/.cert-sudo-sock 文件路径回退）
    → 通过 → 免密放行
```

wrapper 写 SSH_AUTH_SOCK 到 `/tmp/.cert-sudo-sock`，供 PAM 路径的 cert-sudo-check 读取（sudo 的 env_reset 清掉了环境变量）。

优点：
- 不需要 `CAP_SYS_ADMIN`（无需 `unshare -m`）
- 拦截所有 sudo 调用（包括 `/usr/bin/sudo` 绝对路径）
- 包管理器升级时 wrapper 不受影响（dpkg-divert 保护）
- 退出作用域后不留下任何痕迹

### 问题：cert-sudo-check 找不到 SSH agent

PAM 环境下 `pam_exec.so` 不继承用户 shell 的 `SSH_AUTH_SOCK` 环境变量。
且 sudo 的 `env_reset` 会在启动时清空环境。

**解决方案 v9：环境变量 + 临时文件双重回退**

```
1. 快速路径：直接使用 $SSH_AUTH_SOCK（wrapper 调用时环境可用）
2. 文件兜底：读 /tmp/.cert-sudo-sock（wrapper 写入，PAM 路径使用）
3. 都不行 → exit 1（拒绝 sudo）
```

注意：不再使用 /proc 进程树遍历或磁盘扫描。证书验证完全依赖 SSH agent 转发。`cert-operator ssh` 始终使用 `-A` 转发 agent。

### 问题：CA 重置后证书签名不匹配

管理员 `reset ca` 或 `rm -rf data/ && init` 后，所有已签发的 SSH 证书立即失效。
客户端旧证书文件仍在本地，但 CA 指纹不匹配。

**解决方案**：删除旧证书 → 重新 `get-sub_cert` → 新证书与新 CA 匹配。
无需重新 deploy.sh（HTTPS/mTLS 证书独立于 CA 密钥）。

## 关键测试结论

### dpkg-divert sudo wrapper（Docker 测试验证通过）

```
Test A: sudo -n whoami (cert OK)  → root    ✅ 免密码
Test B: sudo -n whoami (cert FAIL) → needpassword  ✅ 拒绝
Test C: sudo whoami (no -n)        → root    ✅ 正常通过
Test D: /usr/bin/sudo -n whoami    → root    ✅ 绝对路径也拦截
Test E: 连续 3 次 sudo 调用        → root    ✅ 多次调用稳定
```

### cert-sudo-check v9（Docker 测试验证通过）

```
有 agent 转发 + $SSH_AUTH_SOCK 环境变量    → cert OK ✅
有 agent 转发 + /tmp/.cert-sudo-sock 文件  → cert OK ✅
无 agent 转发                               → exit 1  ❌ 拒绝
```

### cert-operator ssh CLI 行为

1. 启动 ssh-agent → `ssh-add <key>` 加载证书
2. SSH `-A`（启动 agent forwarding）
3. remote 命令直接执行（无需 mount namespace）
4. wrapper 拦截 `sudo -n`，调 cert-sudo-check
5. 验证通过 → `exec /usr/bin/_sudo xxx`（去掉 -n）
6. PAM 触发 → cert-sudo-check 二次验证（读 /tmp/.cert-sudo-sock）
7. 命令结束后 agent 自动清理

## Go 服务端功能清单

```
cert-operator init          — 生成 CA 密钥 + HTTPS 证书 + mTLS 证书 + deploy.sh
cert-operator serve         — 启动 HTTPS API 服务器
cert-operator pubkey        — 显示 CA 公钥
cert-operator totp          — TOTP 管理
cert-operator groups        — 组管理 (list/create/delete/users/totp/config)
cert-operator renew-cert    — 重新生成 HTTPS 证书
cert-operator version       — 显示版本
cert-operator reset         — 组件重置
    reset ca               — 重生成 CA 密钥对（所有已发证书失效）
    reset https             — 重生成 HTTPS 证书
    reset client            — 重生成 mTLS 客户端证书
    reset totp <group>      — 重置指定组 TOTP secret
    reset group <name>      — 重置组配置
    reset all               — 完全重启（删除所有数据 re-init）
```

## API 端点

| 端点 | 方法 | 功能 |
|------|------|------|
| /api/get-cert | POST | TOTP + 组认证 → 返回 SSH 子证书 |
| /api/health | GET | 健康检查 |
| /api/info | GET | 组信息 (basic/full) |
| /api/version | GET | 版本号 |

## Docker 测试环境

```bash
docker compose -f test/docker-compose.yml up -d --build
# ca-server:  tester@localhost:2225 (testpass)
# test-target: testuser@localhost:2224 (testpass)
```

两个容器都是纯净 Ubuntu 22.04 + openssh-server + sudo。

## 客户端 CLI 用法

```bash
cert-operator get-cert <server> <totp> <name> [--group G] [--user U]
cert-operator ssh <host> <user> <key> [command] [--port N]
cert-operator deploy [script]
cert-operator version
```

`ssh` 子命令内部自动：
1. 启动 ssh-agent + ssh-add 加载证书
2. 用 `-A` 转发 agent
3. 直接执行命令（目标服务器上 sudo wrapper 处理拦截）
4. 命令结束后自动清理 ssh-agent

## 仍需解决

- Hermes 插件需要验证 handler 的 dict 参数传递
- 客户端的 CLI 测试（Docker 测试环境，端到端）<!--已修复: sudo -n + sudo wrapper + agent cleanup 全部通过 -->
