# 安装与卸载指南

## 前置要求

| 组件 | 要求 |
|------|------|
| CA 服务器 | Linux x86_64, root 权限, openssh-server, openssl |
| 客户端 | Linux/macOS/WSL, OpenSSH client |
| 目标服务器 | Linux, OpenSSH server, sudo |

## CA 服务器部署

### 方式一：自解压安装器（推荐）

```bash
# 下载安装器
wget https://github.com/user/cert-operator/releases/download/v3.1.1/ca-server-install-v3.1.1.sh

# 安装
sudo bash ca-server-install-v3.1.1.sh
```

安装过程自动：
1. 检测本机 IP（本地 + 公网）写入 config.json 的 SAN
2. 创建 `cert-operator` 系统用户（无登录权限）
3. 安装 ca-server 二进制
4. 安装 systemd 服务 `cert-operator`
5. 部署 sudo-wrapper + cert-sudo-check + PAM 配置
6. 部署后用户需手动执行 `cert-operator init` 完成初始化

### 方式二：从源码编译

```bash
cd go/ca-server
go build -ldflags="-s -w" -o ca-server ./cmd/ca-server/
sudo bash install.sh
```

### 方式三：手动解压安装

```bash
tar -xzf ca-server-v3.1.1-linux-x86_64.tar.gz
cd ca-server
sudo bash install.sh
```

### 安装后配置

```bash
# 创建管理组
cert-operator groups create admin

# 添加允许用户
cert-operator groups users admin add root

# 配置 TOTP
cert-operator groups totp admin set

# 启动服务
sudo systemctl start cert-operator
sudo systemctl status cert-operator
```

### 更新 SAN

如果服务器 IP 发生变化，需要重新生成 HTTPS 证书：

```bash
# 查看当前 SAN
cert-operator renew-cert

# 更新 SAN（写入配置并重签证书）
cert-operator renew-cert --san "DNS:ca.example.com,IP:1.2.3.4,IP:10.0.0.1"

# 更新后客户端需重新运行 deploy.sh
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"
```

## 客户端部署

### 安装 CLI

```bash
tar -xzf cert-operator-v3.1.1-linux-x86_64.tar.gz
sudo mv cert-operator/cert-operator /usr/local/bin/
cert-operator version   # 确认版本
```

### 部署客户端证书（mTLS）

从 CA 服务器获取客户端证书包并解压：

```bash
# 查看已签发的客户端列表（需要在 CA 服务器上）
cert-operator clients list

# 从服务器复制证书包到本地
scp root@ca-server:/opt/ca_server/data/clients/<name>.tar.gz ./

# 用 CLI 部署
cert-operator deploy-client <name>.tar.gz

# 或手动解压到证书目录
tar -xzf <name>.tar.gz -C ~/.hermes/certs/
```

证书包解压后：

```
~/.hermes/certs/
├── ca-https-cert.pem   # 服务端 HTTPS 证书（验证服务端身份）
├── <name>.key          # 客户端私钥（权限 600）
└── <name>.cert         # 客户端证书（mTLS CA 签发）
```

> 每个客户端使用独立 mTLS 证书，服务端通过 `clients.json` 管理。
> 撤销证书只需 `cert-operator clients revoke <name>`，立即生效。

### 安装 Hermes 插件

```bash
tar -xzf cert-operator-plugin-v3.1.1.tar.gz
mkdir -p ~/.hermes/plugins
cp -r cert-operator-plugin ~/.hermes/plugins/
# 重启 Hermes，工具自动出现
```

## 目标服务器部署

### 部署 sudo wrapper（一键）

在每台需要做 sudo 权限控制的目标服务器上执行：

```bash
# 从 CA 服务器获取部署包
scp root@ca-server:/opt/ca_server/data/dist/deploy-sudo-wrapper.sh root@target:/tmp/
scp root@ca-server:/opt/ca_server/data/dist/sudo-wrapper root@target:/tmp/
scp root@ca-server:/opt/ca_server/data/dist/cert-sudo-check root@target:/tmp/

# 在目标服务器上执行部署
ssh root@target "bash /tmp/deploy-sudo-wrapper.sh"
```

部署脚本自动：

| 步骤 | 操作 |
|------|------|
| 1 | 安装 `cert-sudo-check` 到 `/usr/local/bin/` |
| 2 | `dpkg-divert` 重命名 `/usr/bin/sudo` → `/usr/bin/_sudo` |
| 3 | 安装 `sudo-wrapper` 到 `/usr/bin/sudo` |
| 4 | 配置 PAM `/etc/pam.d/sudo` 添加 `pam_exec.so cert-sudo-check` |

### 配置 SSH 信任 CA

```bash
# 复制 CA 公钥到目标服务器
scp root@ca-server:/opt/ca_server/data/ca_key.pub root@target:/etc/ssh/ca_key.pub

# 配置 sshd
ssh root@target "echo 'TrustedUserCAKeys /etc/ssh/ca_key.pub' >> /etc/ssh/sshd_config && systemctl restart sshd"
```

### 验证部署

```bash
ssh root@target "
  ls -la /usr/bin/sudo          # 应是 wrapper 脚本（~1.5KB）
  ls -la /usr/bin/_sudo         # 应是真 sudo（~232KB, setuid）
  head -3 /etc/pam.d/sudo       # 应包含 cert-sudo-check
  dpkg-divert --list            # 应显示 sudo diversion
  sudo --version                # 应正常
"
```

## 卸载

### 卸载 sudo wrapper（目标服务器）

```bash
sudo bash deploy-sudo-wrapper.sh --uninstall
```

卸载脚本自动：

| 操作 | 说明 |
|------|------|
| 恢复 `/usr/bin/sudo` | 从 dpkg-divert 恢复真 sudo |
| 删除 `cert-sudo-check` | 移除 `/usr/local/bin/cert-sudo-check` |
| 清理 PAM | 从 `/etc/pam.d/sudo` 移除 cert-sudo-check 行 |
| 清理临时文件 | 删除 `/tmp/.cert-sudo-sock` `/etc/sudoers.d/99-cert-operator` |
| 双重保险 | dpkg-divert 恢复失败则从 `_sudo` mv 回 `sudo` |

验证卸载：

```bash
ls -la /usr/bin/sudo           # 恢复为真 sudo 二进制
sudo --version                 # 应正常
sudo -n whoami                 # 应提示 needpassword
```

如果 sudo 丢失：`apt reinstall -y sudo`

### 卸载 CA 服务器

```bash
# 停止并禁用服务
sudo systemctl stop cert-operator
sudo systemctl disable cert-operator

# 删除数据
sudo rm -rf /opt/ca_server

# 删除用户
sudo userdel cert-operator

# 删除快捷命令
sudo rm -f /usr/local/bin/cert-operator

# 删除 systemd 服务
sudo rm -f /etc/systemd/system/cert-operator.service
sudo systemctl daemon-reload
```

### 卸载 CLI

```bash
sudo rm -f /usr/local/bin/cert-operator
rm -rf ~/.hermes/certs
```

### 卸载 Hermes 插件

```bash
rm -rf ~/.hermes/plugins/cert-operator-plugin
```

## 完整安装示例

```bash
# ===== CA 服务器 =====
wget https://github.com/user/cert-operator/releases/download/v3.1.1/ca-server-install-v3.1.1.sh
sudo bash ca-server-install-v3.1.1.sh
cert-operator groups create admin
cert-operator groups users admin add root
cert-operator groups totp admin set
sudo systemctl start cert-operator

# ===== 客户端 =====
tar -xzf cert-operator-v3.1.1-linux-x86_64.tar.gz
sudo mv cert-operator/cert-operator /usr/local/bin/
cert-operator clients list
scp root@ca-server:/opt/ca_server/data/clients/<name>.tar.gz ./
cert-operator deploy-client <name>.tar.gz

# ===== 目标服务器 =====
scp root@ca-server:/opt/ca_server/data/dist/deploy-sudo-wrapper.sh root@target:/tmp/
ssh root@target "bash /tmp/deploy-sudo-wrapper.sh"
scp root@ca-server:/opt/ca_server/data/ca_key.pub root@target:/etc/ssh/
ssh root@target "echo 'TrustedUserCAKeys /etc/ssh/ca_key.pub' >> /etc/ssh/sshd_config && systemctl restart sshd"

# ===== 获取证书并登录 =====
cert-operator get-cert https://10.0.0.1:8443 123456 my-key --group admin --user root
cert-operator ssh 192.168.1.100 root ~/.hermes/certs/my-key "sudo systemctl status docker"
```
