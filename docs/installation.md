# 安装指南

## 前置要求

| 组件 | 要求 |
|------|------|
| CA 服务器 | Linux (x86_64), root 权限, openssh-server |
| 客户端 | Linux/macOS/Windows WSL, openssh-client |
| 目标服务器 | Linux, openssh-server, sudo, bash |

## CA 服务器部署

### 1. 下载并安装

```bash
# 下载二进制
wget https://github.com/user/cert-operator/releases/download/v2.0.0/ca-server-v2.0.0-linux-x86_64.tar.gz
tar -xzf ca-server-v2.0.0-linux-x86_64.tar.gz

# 安装
sudo cp ca-server /opt/ca_server/bin/ca-server
sudo bash install.sh
# install.sh 会自动:
#   - 创建 cert-operator 用户
#   - 初始化 CA 密钥
#   - 安装 systemd 服务
#   - 配置快捷命令

# 查看状态
sudo systemctl status cert-operator
```

### 2. 配置组和用户

```bash
# 创建管理组
cert-operator groups create admin

# 添加允许用户
cert-operator groups users admin add root

# 配置 TOTP
cert-operator groups totp admin set

# 启用 sudo 权限
cert-operator groups config admin set sudo yes

# 启动服务
sudo systemctl start cert-operator
```

### 3. 部署客户端证书

```bash
# 从 CA 服务器获取部署脚本
scp /opt/ca_server/data/dist/deploy.sh user@client:~

# 在客户端运行
bash ~/deploy.sh
```

## 目标服务器配置

### 配置 SSH CA 信任

```bash
# 复制 CA 公钥到目标服务器
scp /opt/ca_server/data/ca_key.pub root@target-server:/etc/ssh/ca_key.pub

# 配置 sshd
echo "TrustedUserCAKeys /etc/ssh/ca_key.pub" >> /etc/ssh/sshd_config
systemctl restart sshd

# 验证
sshd -T | grep trust
```

### 配置 sudo 权限控制（可选）

在目标服务器上部署 PAM 模块 `cert-sudo-check`，实现基于证书扩展的 sudo 权限控制：

```bash
cp cert-sudo-check /usr/local/bin/cert-sudo-check
chmod +x /usr/local/bin/cert-sudo-check

# 配置 PAM
cat > /etc/pam.d/sudo << 'PAMEOF'
#%PAM-1.0
# cert-operator: SSH 证书扩展检查
auth sufficient pam_exec.so quiet /usr/local/bin/cert-sudo-check
auth sufficient pam_unix.so
auth requisite  pam_deny.so
@include common-auth
@include common-account
@include common-session-noninteractive
PAMEOF
```

工作原理：
- 用户 SSH 登录时携带证书，证书包含 `sudo@cert-operator` 扩展
- `cert-sudo-check` 从 SSH agent 中读取证书，验证签名和扩展
- 有扩展 → sudo 免密码
- 无扩展 → 降级到密码
- 无证书（仅密码登录）→ 降级到密码

## 客户端 CLI 安装

```bash
wget https://github.com/user/cert-operator/releases/download/v2.0.0/cert-operator-v2.0.0-linux-x86_64.tar.gz
tar -xzf cert-operator-v2.0.0-linux-x86_64.tar.gz
chmod +x cert-operator
sudo mv cert-operator /usr/local/bin/
```

## Hermes 插件安装

```bash
mkdir -p ~/.hermes/plugins/cert-operator
wget https://github.com/user/cert-operator/releases/download/v2.0.0/cert-operator-plugin-v2.0.0.tar.gz
tar -xzf cert-operator-plugin-v2.0.0.tar.gz -C ~/.hermes/plugins/cert-operator
# 重启 Hermes，工具自动出现
```
