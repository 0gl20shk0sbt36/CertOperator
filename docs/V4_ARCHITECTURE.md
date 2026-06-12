# CertOperator V4.0 架构设计

## 一、三个身份

### 身份一：CA 服务器（中心管理节点）

**部署**：独立 Linux 服务器  
**组件**：`ca-server` + `install.sh` + mTLS + TOTP  

**职能**：
- 管理多个 target（目标服务器组）
- 为每个 target 生成独立 SSH CA、规则、组版本
- 签发用户 SSH 证书 + agent mTLS 证书
- 提供 API（mTLS + TOTP 保护）
- 审计日志
- 维护 target watch 长连接通道

**目录结构**：

```
/opt/ca_server/
├── config.json                       # 全局配置（端口、监听地址、SAN）
├── data/
│   ├── root-ca/                      # 根 CA（X.509）
│   │   ├── ca_key.pem               # 根 CA 私钥 (0600)
│   │   ├── ca_cert.pem              # 根 CA 自签证书 (0644)
│   │   └── serial.txt               # 签发序号
│   │
│   ├── mtls/                         # mTLS CA（客户端身份）
│   │   ├── mtls_ca_key.pem
│   │   ├── mtls_ca_cert.pem
│   │   └── clients.json              # 已签发 mTLS 客户端证书名单
│   │
│   ├── https/                        # HTTPS 通信证书
│   │   ├── https_key.pem
│   │   └── https_cert.pem
│   │
│   ├── audit/
│   │   └── cert-audit.log            # 签发审计日志
│   │
│   ├── targets/                      # 管理多组目标服务器
│   │   ├── production/
│   │   │   ├── ca_key.pem            # 子 CA 私钥（X.509）
│   │   │   ├── ca_cert.pem           # 子 CA 证书（根 CA 签发）
│   │   │   ├── config.json           # target 级配置
│   │   │   ├── rules.json            # 规则配置层
│   │   │   ├── exec-segments.json    # 执行层（自动编译）
│   │   │   ├── trust-keys            # 所有组 CA 公钥合并
│   │   │   ├── group-versions.json   # 组版本号
│   │   │   ├── agent.cert            # target agent mTLS 证书
│   │   │   ├── agent.key             # target agent mTLS 私钥
│   │   │   └── groups/
│   │   │       ├── admin/
│   │   │       │   ├── ca_key        # SSH CA 私钥 (ed25519)
│   │   │       │   ├── ca_key.pub    # SSH CA 公钥
│   │   │       │   ├── ca_cert.pem   # X.509 审计证书
│   │   │       │   ├── serial.txt
│   │   │       │   ├── rules.json    # 组规则
│   │   │       │   └── group-versions.json
│   │   │       └── dev/
│   │   │           └── ...
│   │   └── staging/
│   │       └── ...
│   │
│   └── scheduled-certs/              # 时段证书缓存
│       └── <hash>.json
│
├── bin/
│   └── ca-server
└── uninstall.sh
```

### 身份二：目标服务器（被管控节点）

**部署**：每台需要管控的 Linux 服务器  
**组件**：sshd + sudo-wrapper + cert-sudo-check + cert-sync  

**职能**：
- 信任 CA 下发的组 CA 公钥（TrustedUserCAKeys）
- 接受用户 SSH 登录（证书验证）
- sudo 时调用 cert-sudo-check v10 验证证书
- cert-sync 建立与 CA 的长连接，实时同步 `ca_keys` 和 `group-versions.json`
- 不主动连接 CA（HTTP Long-Polling Watch 由本端发起）

**目标服务器目录结构**：

```
/etc/ssh/
├── ca_keys              ← 所有组 CA 公钥合并（cert-sync 维护）
└── sshd_config          ← TrustedUserCAKeys /etc/ssh/ca_keys

/opt/ca_server/
├── bin/
│   ├── cert-sync        # 同步守护进程
│   ├── cert-sudo-check  # sudo 验证脚本
│   └── sudo-wrapper     # sudo 拦截脚本
│
├── data/
│   ├── group-versions.json   # 组版本号（cert-sync 维护）
│   ├── sync-version          # 本地同步版本号
│   ├── agent.cert            # 连接 CA 的 mTLS 证书
│   └── agent.key             # 连接 CA 的 mTLS 私钥
│
└── README.md

/usr/bin/sudo           → wrapper 脚本
/usr/bin/_sudo          → 真 sudo（由 deploy-sudo-wrapper.sh 部署）
/usr/local/bin/
  cert-sudo-check       → PAM 调用
```

### 身份三：客户端（用户设备）

**部署**：开发机/运维人员的笔记本  
**组件**：`cert-operator` CLI + mTLS 证书包  

**职能**：
- 向 CA 服务器获取 SSH 证书（TOTP + mTLS）
- 用证书 SSH 到目标服务器
- 获取时段精确证书（get-scheduled-cert）

---

## 二、证书层次

```
根 CA (X.509 自签)
  │
  ├── 子 CA: production (X.509, 根签发)
  │     │
  │     ├── 组 CA: admin (SSH ed25519)
  │     │     └── 签发 → alice@prod SSH 用户证书
  │     │
  │     └── 组 CA: dev (SSH ed25519)
  │           └── 签发 → bob@prod SSH 用户证书
  │
  └── 子 CA: staging (X.509, 根签发)
        │
        ├── 组 CA: admin (SSH ed25519)
        └── 组 CA: devops (SSH ed25519)
```

| 层级 | 密钥类型 | 用途 |
|------|---------|------|
| 根 CA | X.509 (P256/P384) | 签发子 CA 证书，审计 |
| 子 CA | X.509 (P256/P384) | 签发组 CA 的 X.509 证书，审计 |
| 组 CA | SSH ed25519 | 签发用户 SSH 证书 |
| 用户证书 | SSH ed25519 (临时) | 登录 + sudo |

> SSH 层面不需要 X.509 链验证。TrustedUserCAKeys 直接信任所有组 CA 的 ed25519 公钥。

### 级联重签规则

| 变更层级 | 影响 | 操作 |
|---------|------|------|
| 根 CA 轮换 | 所有子 CA 的 X.509 证书需重签 | `ca-server root-ca rotate` |
| 子 CA 轮换 | 该 target 下所有组的 X.509 证书需重签 | `ca-server targets <name> ca rotate` |
| 组 CA 轮换 | 该组所有用户证书立即失效 | `ca-server targets <name> groups <g> rotate` |

---

## 三、规则系统

### 规则配置层

每个组的规则配置，管理员直接操作，允许冲突。按 priority 从大到小逐个覆盖生成执行层。

```json
{
  "issue_rules": [
    {
      "id": "admin-day",
      "priority": 10,
      "windows": [
        {"weekdays": [1,2,3,4,5], "start": "09:00", "end": "18:00"}
      ],
      "config": { "totp_required": false, "max_count": 50 }
    },
    {
      "id": "admin-night",
      "priority": 100,
      "windows": [
        {"weekdays": [1,2,3,4,5], "start": "18:00", "end": "09:00"}
      ],
      "config": { "totp_required": true, "max_count": 10 }
    }
  ],
  "judge_rules": [
    {
      "id": "admin-sudo-day",
      "priority": 10,
      "windows": [
        {"weekdays": [1,2,3,4,5], "start": "09:00", "end": "12:00"},
        {"weekdays": [6], "start": "09:00", "end": "12:00"}
      ],
      "config": { "sudo_allowed": true }
    }
  ]
}
```

### 执行层（自动编译）

规则配置层输入，按优先级编译。相同 priority 的按配置顺序靠后覆盖靠前。遇到冲突的时间窗口自动拆分为不冲突的多个时间段。每个时间段对应唯一的 issue 和 judge 状态。

### 规则特性

- 不允许跨天
- 时间窗口左闭右开 [start, end)，精确到分钟
- 默认规则：未匹配时 `totp_required=true, sudo_allowed=false, max_count=0`

---

### 目标服务器 agent mTLS 证书

目标服务器同步通道使用独立的 mTLS 证书体系：

| 证书 | 签发方 | 用途 |
|------|--------|------|
| `agent.cert` + `agent.key` | CA 服务器（`ca-server targets issue-agent <target>`） | 目标服务器 ↔ CA 的同步通信 |

同步通道端点要求 agent mTLS（不是用户的 mTLS 证书），所以目标服务器无法通过用户 API 做同步。

```
CA 端 VerifyPeerCertificate → 检查证书 CN 前缀 "agent-<target>"
目标服务器端 → 检查 CA 服务器的 mTLS CA 签名
```

---

## 四、API 端点

| 端点 | 方法 | mTLS 要求 | 说明 |
|------|------|-----------|------|
| `/api/v1/get-cert` | POST | ✅ | 签发 SSH 证书 |
| `/api/v1/get-scheduled-cert` | POST | ✅ | 时段精确证书 |
| `/api/v1/health` | GET | ✅ | 健康检查 |
| `/api/v1/info` | GET | ✅ | 组信息查询 |
| `/api/v1/version` | GET | ✅ | 版本号 |
| `/api/v1/targets` | GET | ✅ | 列出可用的 target |
| `/api/v1/targets/<name>/sync` | GET | agent mTLS | 目标服务器拉取数据 |
| `/api/v1/targets/<name>/watch` | GET | agent mTLS | 长连接变更通知 |
| `/api/v1/schedule/request` | POST | ✅ | 提交定期免密申请 |
| `/api/v1/schedule/requests` | GET | ✅ | 查看申请 |
| `/api/v1/schedule/replace` | PUT | ✅ | 覆盖申请 |
| `/api/v1/schedule/approved` | GET/DELETE | ✅ | 查看/撤回已生效规则 |

---

## 五、证书扩展字段

签发的 SSH 证书包含以下扩展：

| 扩展 | 示例 | 说明 |
|------|------|------|
| `target@cert-operator` | production | 所属 target |
| `issuer@cert-operator` | ca-primary | 签发 CA 标识 |
| `group@cert-operator` | admin | 所属组 |
| `group-version@cert-operator` | admin-v3 | 组版本号 |
| `sudo@cert-operator` | （无值） | 是否允许 sudo |

---

## 六、cert-sudo-check v10 验证链

```
1. 读取 SSH agent 中所有证书
2. 对每个证书：
   ├── CA 签名验证（sshd TrustedUserCAKeys 已在登录时验证）
   ├── 解析 target@cert-operator 扩展
   ├── 解析 group@cert-operator 扩展
   ├── 解析 group-version@cert-operator 扩展
   ├── 读 /opt/ca_server/data/group-versions.json
   │     └── 该组当前版本是否匹配证书中的版本？
   ├── 检查 sudo@cert-operator 扩展
   │     ├── 存在 → exit 0（允许 sudo）
   │     └── 不存在 → exit 1（拒绝）
   └── 任一验证失败 → 继续下一个证书
3. 全失败 → exit 1
```

---

## 七、同步通道

目标服务器通过 HTTP Long-Polling Watch 与 CA 保持长连接。所有同步请求使用独立的 agent mTLS 证书双向加密：

```
目标服务器 cert-sync:
  # 发起：双向 TLS 连接，出示 agent.cert，验证 CA 的 HTTPS 证书
  curl --cert /opt/ca_server/data/agent.cert \
       --key /opt/ca_server/data/agent.key \
       --cacert /opt/ca_server/data/ca-https-cert.pem \
       "https://ca-server:8443/api/v1/targets/production/watch?version=7"

  └── 连接阻塞在 CA 服务器端
  └── CA 端验证：
      ├── 签名验证（agent 证书由 CA 的 mTLS CA 签发）
      └── CN 检查：前缀必须是 "agent-<target>"（如 "agent-production"）
  └── 规则变更 → CA 递增版本 → 通知连接 → 返回 {"version":8, "changed":true}
  └── 目标拉取 /sync → 更新本地 ca_keys + group-versions
  └── 重建 watch 连接
```

### 同步数据加密

| 保护层 | 方式 |
|--------|------|
| 传输加密 | TLS 1.2+（HTTPS 证书） |
| 双向身份 | mTLS（agent.cert + ca-https-cert.pem） |
| 访问控制 | CA 端 VerifyPeerCertificate 拒绝非 agent 证书 |

---

## 八、组件清单

| 组件 | 语言 | 部署位置 | 功能 |
|------|------|---------|------|
| ca-server | Go（零外部依赖） | CA 服务器 | API 服务器 |
| cert-operator | Go（零外部依赖） | 客户端 | CLI：获取证书、SSH、管理 |
| cert-sudo-check v10 | Bash | 目标服务器 | PAM 模块：sudo 验证 |
| sudo-wrapper | Bash | 目标服务器 | sudo 拦截 |
| cert-sync | Bash | 目标服务器 | CA 同步守护进程 |
| cert-operator-plugin | Python | 客户端 | Hermes AI 插件 |
| install.sh | Bash | CA 服务器 | 一键安装 |
| deploy-sudo-wrapper.sh | Bash | 目标服务器 | 目标服务器部署 |

---

## 九、版本

当前设计版本：**v4.0.0**（待实现）

相比 v3.2.0 的变化：
- 引入 root CA + 子 CA + 组 CA 三层证书体系
- 引入 target 概念（一组目标服务器共享规则和 CA）
- 组级独立的 SSH CA，替换组配置的扩展
- 规则系统（配置层 + 执行层）替换旧的 schedule 申请-审批
- 组版本号机制实现规则变更时旧证书即时失效
- 目标服务器长连接同步替换手动 scp
