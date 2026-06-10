# 服务端管理手册

cert-operator 是 cert-operator 系统的核心组件，提供 CA 密钥管理、HTTPS API 服务、TOTP 验证、组管理和证书签发功能。

## 命令一览

```bash
cert-operator init                        # 首次初始化
cert-operator serve [flags]               # 启动 HTTPS API
cert-operator pubkey                      # 显示 CA 公钥指纹
cert-operator totp <action> [flags]       # TOTP 管理
cert-operator groups <action> [args...]   # 组管理
cert-operator renew-cert [--san "..."]    # 重新生成 HTTPS 证书
cert-operator reset <mode>                # 重置组件
cert-operator version                     # 显示版本
```

---

## init — 初始化

首次初始化，生成所有密钥和证书。**只能运行一次**（数据目录已存在则拒绝）。

### 流程

```
init 自动完成：
  1. 生成 CA 密钥对（ed25519）
  2. 生成 HTTPS 自签证书（含 config.json 中的 SAN）
  3. 初始化序列号计数器（serial.txt = 0）
  4. 生成 mTLS 客户端证书
  5. 生成 deploy.sh（客户端部署脚本）
  6. 输出目标服务器配置指引
```

### 用法

```bash
cert-operator init
```

### 前置条件

- 必须存在 `config.json`（install.sh 自动创建）
- 如果 SAN 需要手动指定，先编辑 config.json 再加入 `server.san`
- 也可以 init 后用 `renew-cert --san` 更新

### 输出示例

```bash
$ cert-operator init
🔨 Generating CA key pair (ed25519)...
   ✅ CA private key: /opt/ca_server/data/ca_key
   ✅ CA public key:  /opt/ca_server/data/ca_key.pub
🔨 Generating HTTPS self-signed certificate...
   SAN: [DNS:localhost IP:127.0.0.1 IP:10.0.0.1 IP:1.2.3.4]
   ✅ HTTPS key:  /opt/ca_server/data/https_key.pem
   ✅ HTTPS cert: /opt/ca_server/data/https_cert.pem
   ✅ Serial counter: /opt/ca_server/data/serial.txt (initial value 0)
🔨 Generating mTLS client certificate...
   ✅ Client key:  /opt/ca_server/data/client.key
   ✅ Client cert: /opt/ca_server/data/client.cert
📦 Client deploy package (three files, one transfer):
   scp /opt/ca_server/data/dist/deploy.sh user@client:~/
   Client runs: bash ~/deploy.sh

📋 Target server configuration commands:
  scp /opt/ca_server/data/ca_key.pub root@target-server:/etc/ssh/ca_key.pub
  echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config
  systemctl restart sshd
```

---

## serve — 启动 API 服务

启动 HTTPS API 服务器，默认监听 `0.0.0.0:8443`。

### 用法

```bash
# 基本（使用 config.json 中的监听设置）
cert-operator serve

# 指定地址和端口
cert-operator serve --host 10.0.0.1 --port 8443

# 禁用 mTLS（不推荐生产使用）
cert-operator serve --no-mtls

# 调试模式（更多日志）
cert-operator serve --debug
```

### 参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `--host` | string | config.json 中的 host | 监听地址 |
| `--port` | int | config.json 中的 port | 监听端口 |
| `--no-mtls` | bool | false | 禁用 mTLS（默认开启） |
| `--debug` | bool | false | 启用调试日志 |

### API 端点

| 端点 | 方法 | 功能 | mTLS 要求 |
|------|------|------|-----------|
| `/api/get-cert` | POST | 验证 TOTP + 签发 SSH 证书 | 是 |
| `/api/health` | GET | 健康检查 | 是 |
| `/api/info` | GET | 组信息 | 是 |
| `/api/version` | GET | 版本号 | 是 |

所有端点都走 HTTPS（TLS 1.2+），mTLS 默认开启。

### 启动日志

```bash
$ cert-operator serve
cert-operator v3.0.0 — serving on https://0.0.0.0:8443
  CA ready: true
  rate limit: 5/300s
  mTLS: enabled
```

### systemd 方式

```bash
# 启动
sudo systemctl start cert-operator

# 查看状态
sudo systemctl status cert-operator

# 查看日志
journalctl -u cert-operator -f

# 停止
sudo systemctl stop cert-operator

# 重启
sudo systemctl restart cert-operator
```

---

## pubkey — 显示 CA 公钥

显示 CA 公钥指纹，用于验证和对比。

### 用法

```bash
cert-operator pubkey
```

### 输出

```bash
$ cert-operator pubkey
256 SHA256:IBsBADQP22Jk531XWYxetgxqCRIIDhv1to/Bn5M0iRM root@ca-server (ED25519)
```

可用于验证：
- 目标服务器上的 `ca_key.pub` 是否一致
- 客户端证书的签名 CA 是否匹配

---

## groups — 组管理

cert-operator 使用组来控制用户权限。每个组配置独立的：
- 允许用户（allowed_users）
- TOTP 密钥
- 证书有效期
- 证书扩展（如 sudo 权限）
- 冻结状态

### 子命令

#### list — 列出所有组

```bash
cert-operator groups list
```

输出：
```
Groups:
  default     (frozen)
    users: user1,user2
  admin       (active)
    users: root,devops
    parent: default
    sudo: yes
```

#### create — 创建组

```bash
cert-operator groups create devops
```

#### delete — 删除组（仅删除配置，TOTP 保持）

```bash
cert-operator groups delete devops
```

#### users — 管理组成员

```bash
# 添加用户
cert-operator groups users admin add root
cert-operator groups users admin add deploy

# 移除用户
cert-operator groups users admin remove deploy

# 列出用户
cert-operator groups users admin list
```

#### totp — 管理组 TOTP

```bash
# 设置新 TOTP（生成新 secret 并显示二维码 URL）
cert-operator groups totp admin set

# 验证 TOTP 同步
cert-operator groups totp admin verify
```

#### config — 配置组属性

```bash
# 设置 sudo 权限
cert-operator groups config admin set sudo yes
cert-operator groups config admin set sudo no

# 设置证书有效期（分钟）
cert-operator groups config admin set validity-minutes 120

# 设置父组（用于继承）
cert-operator groups config admin set parent default
cert-operator groups config admin set parent none

# 设置允许用户
cert-operator groups config admin set allowed-users root,deploy

# 冻结组（停止签发证书）
cert-operator groups config admin set frozen yes
cert-operator groups config admin set frozen no
```

### 组继承

组可以指定父组（`parent`），继承部分属性。

#### 继承规则

| 属性 | 继承方式 |
|------|----------|
| `allowed_users`（允许用户） | **并集**：父组用户 + 子组用户合并 |
| `extensions`（证书扩展） | **子组覆盖**：子组有则用子组的，没有则用父组的 |
| `sudo` 扩展 | 同 extensions，子组可独立设置 `yes`/`no` |
| `totp_secret`（TOTP） | **子组优先**：子组有自己的则用自己的，没有则继承父组的 |
| `validity_minutes`（有效期） | 子组有则覆盖，没有则继承 |
| `frozen`（冻结状态） | 子组有则覆盖，没有则继承 |

#### 典型用法

```bash
# 创建基础组（无 sudo）
cert-operator groups create base
cert-operator groups users base add user1
cert-operator groups totp base set

# 创建 sudo 组，继承 base 的用户，覆盖扩展
cert-operator groups create with-sudo
cert-operator groups config with-sudo set parent base
cert-operator groups config with-sudo set sudo yes
cert-operator groups totp with-sudo set   # 独立 TOTP，与 base 区分
```

效果：
- `base` 允许用户：`[user1]`，用自己 TOTP 签证书 → 无 sudo
- `with-sudo` 允许用户：`[user1]`（从 base 继承），用自己 TOTP 签证书 → 有 sudo
- `user1` 有两组证书，分别对应不同权限，由不同 TOTP 保护

#### 示例配置

```json
{
  "groups": {
    "base": {
      "allowed_users": "root,user1",
      "extensions": {"sudo": "no"}
    },
    "devops": {
      "parent": "base",
      "allowed_users": "deploy",
      "extensions": {"sudo": "yes"}
    }
  }
}
```

`devops` 组解析结果：
- 允许用户：`root,user1,deploy`（并集）
- 证书扩展：`sudo=yes`（自己覆盖）
- TOTP：用自己的 secret（如果没设则继承 base 的）

### default 组

系统默认组。如果 config.json 中没有定义，init 会自动创建。
首次使用需要配置 TOTP（`cert-operator groups totp default set`）。

---

## totp — TOTP 管理

管理 default 组的 TOTP。等同于 `cert-operator groups totp default <action>`。

**注意：`cert-operator totp --set 只能操作 default 组。**
要为其他组配置 TOTP，必须用：

```bash
cert-operator groups totp admin set
cert-operator groups totp devops set
```

当前服务器已配置的组可通过 `cert-operator groups list` 查看。

### 用法

```bash
# 设置 TOTP（生成新密钥并显示二维码）
cert-operator totp --set

# 验证 TOTP 同步（输入当前码确认）
cert-operator totp --verify
```

### 输出示例

```bash
$ cert-operator totp --set
TOTP secret: JBSWY3DPEHPK3PXP
TOTP URI:    otpauth://totp/CertOperator:admin?secret=JBSWY3DPEHPK3PXP&issuer=CertOperator&algorithm=SHA1&digits=6&period=30
1. 在手机 Authenticator App 中添加账户
   手动输入: CertOperator:admin
   密钥:     JBSWY3DPEHPK3PXP
   或扫码:   [二维码 ASCII 图案]
2. 输入 cert-operator totp --verify 确认同步成功
```

---

## renew-cert — 重新生成 HTTPS 证书

不修改 CA 密钥或客户端证书，仅重新生成 HTTPS 自签证书。

### 用法

```bash
# 使用 config.json 中的 SAN 重新签发
cert-operator renew-cert

# 更新 SAN 并重新签发（同时保存到 config.json）
cert-operator renew-cert --san "DNS:ca.example.com,IP:1.2.3.4,IP:10.0.0.1"
```

### 注意事项

- 重新签发后，客户端需要重新运行 `deploy.sh` 获取新证书
- `--san` 参数会同时更新 `config.json` 和证书
- 不带 `--san` 则使用 config.json 中的 `server.san` 值

```bash
$ cert-operator renew-cert --san "IP:1.2.3.4,IP:10.0.0.1"
   SAN: IP:1.2.3.4,IP:10.0.0.1
   ✅ config.json 已更新
🔨 Regenerating HTTPS self-signed certificate...
   SAN: [IP:1.2.3.4 IP:10.0.0.1]
   ✅ HTTPS cert updated: /opt/ca_server/data/https_cert.pem
   ✅ Deploy script: /opt/ca_server/data/dist/deploy.sh (755 bytes)
   ⚠️  客户端需重新运行 deploy.sh 获取新证书
```

---

## reset — 组件重置

重置 CA 服务器的各个组件。

### 用法

```bash
cert-operator reset <mode>

mode:
  ca             重生成 CA 密钥对（所有已签发证书立即失效！）
  https          重生成 HTTPS 证书
  client         重生成 mTLS 客户端证书 + deploy.sh
  totp <group>   重置指定组的 TOTP secret
  group <name>   重置组配置为默认值
  all            完全重置（删除所有数据重新 init）
```

### 各模式说明

#### reset ca — 重生成 CA 密钥对

```bash
cert-operator reset ca
```

影响：
- 所有已签发的 SSH 证书立即失效
- 需要在所有目标服务器上重新部署 CA 公钥
- 客户端需要重新获取证书

#### reset https — 重生成 HTTPS 证书

```bash
cert-operator reset https
```

等同于 `renew-cert`。HTTPS 证书更新后客户端需重新运行 `deploy.sh`。

#### reset client — 重生成 mTLS 证书

```bash
cert-operator reset client
```

影响：
- 重新生成客户端证书和 deploy.sh
- 所有客户端需重新运行 deploy.sh

#### reset totp <group> — 重置组 TOTP

```bash
cert-operator reset totp admin
```

- 生成新的 TOTP secret
- 原来的 TOTP 令牌立即失效
- 用户需要重新在 App 中添加账户

#### reset group <name> — 重置组配置

```bash
cert-operator reset group devops
```

- 清空组的所有自定义配置
- 恢复为默认值（允许用户为空、扩展为空）
- TOTP secret 保留

#### reset all — 完全重置

```bash
cert-operator reset all
```

⚠️ 删除 `/opt/ca_server/data/` 下所有数据，然后重新执行 `init`。
所有已签发的证书、TOTP 配置、CA 密钥全部丢失。

---

## version — 版本信息

```bash
cert-operator version
cert-operator v3.0.0
```

---

## config.json 路径

所有命令默认读取当前目录的 `config.json`。可通过环境变量指定：

```bash
CA_SERVER_CONFIG=/path/to/config.json cert-operator serve
```

## 常见任务场景

### 首次部署

```bash
# 1. 安装
sudo bash ca-server-install-v3.0.0.sh

# 2. 创建管理组和 TOTP
cert-operator groups create admin
cert-operator groups users admin add root
cert-operator groups totp admin set

# 3. 启动服务
sudo systemctl start cert-operator

# 4. 部署客户端证书
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"

# 5. 配置目标服务器
scp /opt/ca_server/data/ca_key.pub root@target:/etc/ssh/ca_key.pub
ssh root@target "echo 'TrustedUserCAKeys /etc/ssh/ca_key.pub' >> /etc/ssh/sshd_config && systemctl restart sshd"
```

### 服务器 IP 变更

```bash
# 更新 SAN
cert-operator renew-cert --san "IP:new.ip.address"

# 重新部署客户端证书
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"
```

### CA 密钥泄露

```bash
# 1. 重置 CA
cert-operator reset ca

# 2. 重新部署 CA 公钥到所有目标服务器
scp /opt/ca_server/data/ca_key.pub root@target1:/etc/ssh/
ssh root@target1 "systemctl restart sshd"

# 3. 通知所有客户端重新获取证书
# 删除旧证书 → 重新 get-cert
```
