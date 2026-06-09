# cert-operator

通过 TOTP + mTLS 双层认证，经 HTTPS 从 CA 服务器获取 SSH 子证书，实现零信任远程登录。

## 架构

```
用户/TOTP App ──(6位码)──▶ Hermes AI ──(HTTPS + mTLS)──▶ CA 服务器 ──(SSH 证书)──▶ 目标服务器
                              │                           │                        │
                           client.cert                 ca_key.pub              ca_key.pub
                           client.key                  https_cert.pem           TrustedUserCAKeys
                           ca-https-cert.pem            client.cert (verify)
```

**传输层**：mTLS 双向证书验证 — 客户端持有 `client.cert`，服务端要求 `CERT_REQUIRED`
**应用层**：TOTP 6 位一次性码 — 限速 5 次/300 秒
**签名层**：SSH CA 签名 — 证书有效期默认 60 分钟（可配），自动过期

## 文件结构

```
workspace/
├── ca_server/                   ← CA 服务端
│   ├── ca_server.py             # 子命令（含 groups、users、renew-cert 等）
│   ├── config.yaml              # 配置（证书有效期、组、限速等）
│   ├── requirements.txt         # flask, pyotp, pyyaml
│   ├── package.sh               # 打包自解压安装脚本
│   ├── install.sh               # 安装脚本（被 package.sh 嵌入）
│   ├── uninstall.sh             # 卸载脚本
│   └── ca_setup.sh              # 开发环境快速设置
│
├── cert-operator/               ← 调用版（Python 包 + CLI）
│   ├── __init__.py              # 注册入口
│   ├── __main__.py              # CLI 入口
│   ├── client.py                # get_sub_cert / ssh_with_cert
│   ├── tools.py                 # schema + handler
│   ├── plugin.yaml
│   └── pyproject.toml
│
├── cert-operator-plugin/        ← 插件版（Hermes 单文件插件）
│   ├── __init__.py              # 全部逻辑（452 行）
│   └── plugin.yaml
│
├── disk-cleanup/                ← 参考：hooks 注册模式
└── plugins.py                   ← PluginContext 完整 API
```

## 快速开始

### 服务端（生产部署）

```bash
# 1. 打包自解压安装脚本
bash ca_server/package.sh
# 生成: release/ca-server-install.sh （一个文件，包含全部）

# 2. 上传到服务器并安装
scp release/ca-server-install.sh root@server:~
ssh root@server
# 国内服务器建议先设置镜像源加速
export PIP_INDEX_URL=https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
bash ca-server-install.sh
# 自动完成：创建用户 → 解压 → venv → 依赖 → init → 开机自启
#           → 自动配置本机 SSH 信任 CA 公钥
#           → 安装 cert-operator 快捷命令

# 3. 配置管理员组（含 TOTP + sudo 权限）
cert-operator groups create admin
cert-operator groups users admin add root,yyx
cert-operator groups totp admin set          # 手机扫码绑定
cert-operator groups config admin --sudo yes # 证书带 sudo 扩展

# 4. 配置普通用户组（仅 SSH，无 sudo）
cert-operator groups create operator
cert-operator groups users operator add yyx
cert-operator groups totp operator set

# 5. 开放防火墙（默认端口 8443）
sudo ufw allow 8443/tcp

# 6. 启动服务
sudo systemctl start cert-operator

# 7. 查看 CA 公钥部署到目标服务器的指南
cert-operator pubkey

# 8. 客户端部署包
scp /opt/ca_server/dist/deploy.sh user@client:~
# 客户端运行: bash deploy.sh
```

### 服务端（开发/测试）

```bash
cd ca_server

pip3 install --break-system-packages -r requirements.txt
pip3 install --break-system-packages "requests>=2.31"

python3 ca_server.py init                          # 初始化
python3 ca_server.py groups create default         # 创建默认组
python3 ca_server.py groups users default add root # 添加用户
python3 ca_server.py totp                          # 配置全局 TOTP
python3 ca_server.py serve                         # 启动 mTLS 服务
```

### 客户端安装与使用

#### 安装方式

**方式一：Hermes 插件（推荐）**

```bash
cp -r cert-operator-plugin ~/.hermes/plugins/cert-operator-plugin
bash ~/deploy.sh   # 部署客户端证书
```

**方式二：独立 CLI**

```bash
pip install requests
python3 -m cert-operator get-cert https://server:8443 123456 prod-server
```

**方式三：Python 包**

```bash
pip install -e /workspace/cert-operator
from cert_operator.client import get_sub_cert
```

#### 基本用法

```bash
# 获取证书
python3 -m cert-operator get-cert https://server:8443 123456 prod-server

# 指定用户和组
python3 -m cert-operator get-cert https://server:8443 123456 prod-server \
    --user root --group admin

# SSH 登录
python3 -m cert-operator ssh server.example.com root ~/.hermes/certs/prod-server
```

## 用户组管理

### 组概念

每组拥有独立的配置（TOTP Secret、证书有效期、允许用户、sudo 权限）。

**层级继承**：组可以设置 `parent`，子组自动继承父组的 `allowed_users`（合并）、`extensions`（合并覆盖），其余字段子组覆盖父组。

```yaml
groups:
  operator:
    allowed_users: "yyx"
    validity_minutes: 60
    totp_secret: "xxx"
    parent: ""
    extensions: {}

  admin:
    parent: "operator"            # 继承 operator 的用户
    validity_minutes: 10          # 覆盖：10 分钟
    extensions:
      sudo: "yes"                # 证书包含 sudo@cert-operator 扩展
```

### 命令参考

```bash
cert-operator groups list                         # 列出所有组
cert-operator groups create <name>                # 创建组
cert-operator groups delete <name>                # 删除组

cert-operator groups users <name> add <user>      # 添加组成员
cert-operator groups users <name> remove <user>   # 移除组成员
cert-operator groups users <name> list            # 列出组成员

cert-operator groups totp <name> set              # 配置组 TOTP
cert-operator groups totp <name> verify           # 查看当前验证码

cert-operator groups config <name> get              # 查看组配置
cert-operator groups config <name> set \            # 修改组配置
    --parent operator \                              #  设置父组
    --validity-minutes 10 \                          #  设置有效期（分钟）
    --sudo yes \                                    #  开启 sudo 扩展
    --frozen yes                                    #  冻结组（停止签发）
```

## 证书扩展（sudo）

当组配置了 `extensions.sudo: "yes"`，签发的 SSH 证书会包含自定义扩展 `sudo@cert-operator`。目标服务器需要安装并配置 [pam-ussh](https://github.com/uber/pam-ussh) 来读取该扩展。

```bash
# 检查已签发的证书扩展
ssh-keygen -L -f ~/.hermes/certs/my-server-cert.pub
# 输出示例：
#   Extensions:
#     sudo@cert-operator UNKNOWN FLAG OPTION
```

### 目标服务器配置（另一台机器）

如果目标服务器和 CA 服务器是同一台机器，安装脚本已自动配置 `TrustedUserCAKeys`（CA 公钥信任），**可直接用证书 SSH 登录**。pam-ussh 需手动安装。

如需部署到其他目标服务器，每台都执行以下步骤：

```bash
# ------------------------------------------
# A. 基础配置（证书 SSH 登录）
# ------------------------------------------
# 1. 复制 CA 公钥
scp ca-server:/opt/ca_server/data/ca_key.pub /etc/ssh/ca_key.pub

# 2. 配置 sshd 信任
echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config
systemctl restart sshd

# ------------------------------------------
# B. sudo 权限控制（cert-sudo-check）
# ------------------------------------------
# 3. 复制 sudo 检查脚本（从 CA 服务器或本机）
scp ca-server:/opt/ca_server/cert-sudo-check /usr/local/bin/cert-sudo-check
chmod +x /usr/local/bin/cert-sudo-check

# 4. 配置 sudo 使用 pam_exec 调用该脚本
#    有 sudo 扩展 → 直接 sudo（不输密码）
#    无扩展/无证书/非我们 CA 签发 → 降级到密码 sudo
cat > /etc/pam.d/sudo << 'PAM'
auth sufficient pam_exec.so /usr/local/bin/cert-sudo-check
auth sufficient pam_unix.so
PAM

# 5. 客户端 SSH 必须开启 Agent Forwarding
#    cert-sudo-check 从 SSH Agent 读取证书
```

> **签发证书时的 principals 策略**：
>
> | 组 | 允许用户 | 签发方式 | 证书 principals | 用途 |
> |-----|---------|---------|----------------|------|
> | admin | `aibot` | --sudo yes | `aibot` + sudo@cert-operator 扩展 | SSH 以 aibot 登录，sudo 放行 |
> | aiuser | `aibot` | 不配置 sudo | `aibot` | SSH 以 aibot 登录，sudo 被拒绝 |
>
> 控制 sudo 权限的是证书扩展 `sudo@cert-operator`，不是 principal。admin 组的 `groups config --sudo yes` 会自动将该扩展写入证书。
>
> **客户端 SSH 时必须用 `ssh -A`**（Agent Forwarding），否则 cert-sudo-check 无法读取证书。

## 子命令参考

### ca_server.py（快捷命令: cert-operator）

| 命令 | 作用 |
|------|------|
| `init` | 初始化 CA 密钥、HTTPS 证书、mTLS 客户端证书 |
| `renew-cert` | 重新生成 HTTPS 证书（更新 SAN，不碰 CA 密钥） |
| `serve` | 启动 mTLS HTTPS 服务 |
| `serve --no-mtls` | 禁用 mTLS，仅单向 HTTPS |
| `serve --port 8443` | 指定端口（默认 8443） |
| `users add <user>` | 添加 default 组的允许用户 |
| `groups list` | 列出所有组 |
| `groups create <name>` | 创建组 |
| `groups delete <name>` | 删除组 |
| `groups users <name> add <user>` | 添加组成员 |
| `groups totp <name> set` | 配置组 TOTP |
| `groups config <name> get` | 查看组配置 |
| `groups config <name> set` | 修改组配置（--sudo / --parent / --validity-minutes / --frozen） |
| `totp` | 配置 default 组 TOTP |
| `totp --verify` | 显示当前验证码 |
| `pubkey` | 显示 CA 公钥 + 目标服务器部署命令 |
| `renew-cert` | 重新生成 HTTPS 证书 |

### 插件工具

| 工具 | 作用 |
|------|------|
| `get_sub_cert` | 通过 TOTP + mTLS 获取 SSH 子证书（支持 group、user 参数） |
| `ssh_with_cert` | 使用 SSH 证书登录目标服务器 |

## API 参考

### POST /api/get-cert

```json
{ "totp": "123456", "group": "admin", "user": "root" }
```

| 参数 | 必填 | 说明 |
|------|------|------|
| `totp` | 是 | 6 位 TOTP 一次性验证码 |
| `group` | 否 | 组名（不传则用 default 组） |
| `user` | 否 | 登录用户名（不传则证书包含组内所有允许用户） |

### GET /api/info

返回服务器信息，包括 `groups` 中每个组的配置概要和 TOTP 是否已配置。

## 安全设计

- **mTLS 传输层**：非授权客户端 TLS 握手阶段被拒绝
- **TOTP 应用层**：每个组独立 TOTP，证书签发需验证
- **Rate Limit**：5 次 / 300 秒，防暴力破解
- **用户隔离**：不同组可签不同用户，指定 user 只签单用户
- **sudo 控制**：证书扩展区分普通/管理员权限
- **主机密钥验证**：`StrictHostKeyChecking=accept-new`，持久化 `known_hosts`
- **证书短期有效**：默认 1 小时，每组可独立配置
- **零密钥存储**：服务端签发后立即删除临时密钥对
