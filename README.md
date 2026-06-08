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
**签名层**：SSH CA 签名 — 证书有效期默认 1 小时，自动过期

## 文件结构

```
workspace/
├── ca_server/               ← CA 服务端
│   ├── ca_server.py         # 子命令: init | totp | serve | pubkey | users
│   ├── config.yaml          # 配置（证书有效期、限速、用户等）
│   ├── requirements.txt     # flask, pyotp, pyyaml (可选 qrcode)
│   ├── package.sh           # 打包自解压安装脚本
│   ├── install.sh           # 安装脚本（被 package.sh 嵌入）
│   └── ca_setup.sh          # 开发环境快速设置
│
├── cert-operator/           ← 客户端插件（Hermes 插件格式）
│   ├── plugin.yaml          # 清单
│   ├── __init__.py          # register(ctx) 入口
│   ├── __main__.py          # CLI 入口
│   ├── tools.py             # OpenAI schema + handler
│   └── client.py            # get_sub_cert / ssh_with_cert
│
├── spotify/                 ← 参考：tools 注册模式
├── disk-cleanup/            ← 参考：hooks 注册模式
└── plugins.py               ← PluginContext 完整 API
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
# 自动完成：创建用户 → 解压 → venv → 安装依赖 → init → 开机自启
#           → 自动配置本机 SSH 信任 CA 公钥（TrustedUserCAKeys）
#           安装后本机即可用证书 SSH 登录

# 3. 添加允许 SSH 登录的用户
sudo -u cert-operator /opt/ca_server/.venv/bin/python \
    /opt/ca_server/ca_server.py users add root

# 4. 配置 TOTP（手机扫码绑定）
sudo -u cert-operator /opt/ca_server/.venv/bin/python \
    /opt/ca_server/ca_server.py totp

# 5. 启动服务
sudo systemctl start cert-operator

# 6. 查看 CA 公钥部署到目标服务器的指南
sudo -u cert-operator /opt/ca_server/.venv/bin/python \
    /opt/ca_server/ca_server.py pubkey

# 7. 客户端部署包
scp /opt/ca_server/dist/deploy.sh user@client:~
# 客户端运行: bash deploy.sh
```

### 服务端（开发/测试）

```bash
cd ca_server

# 安装依赖
pip3 install --break-system-packages -r requirements.txt
pip3 install --break-system-packages "requests>=2.31"

# 1. 初始化
python3 ca_server.py init

# 2. 添加允许用户
python3 ca_server.py users add root

# 3. 配置 TOTP
python3 ca_server.py totp

# 4. 启动服务（mTLS 双向验证）
python3 ca_server.py serve

# 5. 查看 CA 公钥部署指南
python3 ca_server.py pubkey
```

### 客户端

```bash
# 获取证书
python3 -m cert-operator get-cert https://ca-server:8443 123456 prod-server

# 登录服务器
python3 -m cert-operator ssh prod-server.example.com root ~/.hermes/certs/prod-server

# 或者直接使用 SSH（证书自动发现）
ssh -i ~/.hermes/certs/prod-server user@target-server
```

## 插件安装

### 方式一：Hermes 插件（推荐）

将 `cert-operator/` 目录复制到 Hermes 用户插件目录即可自动加载：

```bash
cp -r cert-operator ~/.hermes/plugins/cert-operator
# 或从服务器上的安装包直接部署
scp root@ca-server:/opt/ca_server/dist/deploy.sh ~
bash ~/deploy.sh
```

Hermes 启动后会自动检测 `plugin.yaml`，注册 `get_sub_cert` 和 `ssh_with_cert` 两个工具。

验证是否加载成功：

```bash
ls ~/.hermes/plugins/cert-operator/plugin.yaml   # 确认存在
grep -r "cert-operator" ~/.hermes/logs/agent.log  # 查看加载日志
```

### 方式二：作为 Python 包安装

```bash
# 直接安装到系统
pip install -e /workspace/cert-operator

# 或复制到项目内作为本地包
cp -r cert-operator /your-project/
```

导入使用：

```python
from cert_operator.client import get_sub_cert, ssh_with_cert

get_sub_cert("https://ca-server:8443", "123456", "prod-server")
```

### 方式三：独立 CLI（无需安装）

```bash
# 直接运行
python3 -m cert-operator get-cert https://ca-server:8443 123456 prod-server
```

前提是 `requests` 库已安装：`pip install requests`

## 子命令参考

### ca_server.py

| 命令 | 作用 |
|------|------|
| `init` | 初始化 CA 密钥、HTTPS 证书、客户端 mTLS 证书、deploy.sh |
| `totp` | 配置 TOTP（终端二维码 + PNG 保存） |
| `totp --verify` | 显示当前验证码，与手机对比 |
| `totp --regenerate` | 重新生成 Secret |
| `serve` | 启动 mTLS HTTPS 服务 |
| `serve --no-mtls` | 禁用 mTLS，仅单向 HTTPS |
| `pubkey` | 显示 CA 公钥 + 目标服务器部署命令 |
| `users list` | 列出当前允许的 SSH 登录用户 |
| `users add <user>` | 添加允许用户（逗号分隔多个，检查系统用户是否存在） |
| `users add` | 交互式选择本地系统用户 |
| `users remove <user>` | 移除允许用户 |
| `users set <user1,user2>` | 覆盖设置允许用户列表（传空字符串清空） |

### 插件工具

| 工具 | 作用 |
|------|------|
| `get_sub_cert` | 通过 TOTP + mTLS 获取 SSH 子证书 |
| `ssh_with_cert` | 使用 SSH 证书登录目标服务器 |

## 安全设计

- **mTLS 传输层**：非授权客户端在 TLS 握手阶段即被拒绝
- **TOTP 应用层**：所有证书签发必须通过 TOTP 验证
- **Rate Limit**：5 次 / 300 秒，防止暴力破解
- **主机密钥验证**：`StrictHostKeyChecking=yes`，持久化 `known_hosts`
- **证书短期有效**：默认 1 小时，通过 `config.yaml` 可配置
- **零密钥存储**：服务端签发后立即删除临时密钥对

## 环境要求

- Python 3.11+
- OpenSSL（服务端 `init` 需要）
- 依赖安装：`pip3 install --break-system-packages -r ca_server/requirements.txt`
