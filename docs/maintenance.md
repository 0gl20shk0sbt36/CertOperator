# 维护手册

## 日常维护

### 查看 CA 服务器状态

```bash
# 服务状态
systemctl status cert-operator

# 查看日志
journalctl -u cert-operator -n 50 --no-pager

# 实时日志
journalctl -u cert-operator -f
```

### 监控 CA 公钥和证书

```bash
# CA 公钥指纹
cert-operator pubkey

# HTTPS 证书信息
openssl x509 -in /opt/ca_server/data/https_cert.pem -text -noout | grep -A1 "Subject Alternative Name"

# 查看当前 SAN
cert-operator renew-cert  # 会显示当前 SAN
```

### 管理组和用户

```bash
# 列出所有组
cert-operator groups list

# 创建组
cert-operator groups create devops

# 添加用户
cert-operator groups users devops add root
cert-operator groups users devops add deploy

# 配置组属性
cert-operator groups config devops set sudo yes
cert-operator groups config devops set validity-minutes 120

# 冻结组（停止签发）
cert-operator groups config devops set frozen yes

# TOTP 管理
cert-operator groups totp devops set     # 设置新 TOTP
cert-operator groups totp devops verify  # 验证 TOTP 同步
```

### 监控证书签发

```bash
# 查看序列号（已签发证书数量）
cat /opt/ca_server/data/serial.txt

# 查看限流状态（max_attempts / window_seconds）
cat /opt/ca_server/config.json | grep rate_limit -A3
```

## 证书管理

### 更新 HTTPS 证书 SAN

当 CA 服务器 IP 或域名变更时：

```bash
# 更新 SAN 并重新签发
cert-operator renew-cert --san "DNS:ca.example.com,IP:1.2.3.4,IP:10.0.0.1"

# 重新部署客户端证书
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"
```

### 重新生成 CA 密钥对

**注意：这会立即使所有已签发的 SSH 证书失效！**

```bash
# 重新生成 CA 密钥对
cert-operator reset ca

# 重新部署 CA 公钥到所有目标服务器
scp /opt/ca_server/data/ca_key.pub root@target1:/etc/ssh/ca_key.pub
ssh root@target1 "systemctl restart sshd"

# 客户端需要重新获取证书
cert-operator get-cert https://ca-server:8443 123456 my-key --group admin
```

### 重新生成 mTLS 客户端证书

```bash
cert-operator reset client

# 重新部署客户端证书
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"
```

## 故障排查

### 客户端无法获取证书

```bash
# 检查 CA 服务器是否在线
curl -sk --cert ~/.hermes/certs/client.cert \
         --key ~/.hermes/certs/client.key \
         https://<ca-server>:8443/api/health

# 检查 /api/version
curl -sk --cert client.cert --key client.key \
  https://<ca-server>:8443/api/version

# 如果 SSL 证书错误，确认 SAN 是否包含当前连接 IP
# 尝试用 -k 跳过验证

# 如果连接超时，检查防火墙
telnet <ca-server> 8443
```

### SSH 连接成功但 sudo 需要密码

```bash
# 第1步：在目标服务器上检查 sudo wrapper
ssh root@target "file /usr/bin/sudo"
# 输出应为 "Bourne-Again shell script"（不是 ELF）
# 如果是 ELF → wrapper 未部署，运行 deploy-sudo-wrapper.sh

# 第2步：检查 cert-sudo-check
ssh root@target "ls -la /usr/local/bin/cert-sudo-check"
# 如果文件不存在 → 重新部署

# 第3步：检查 PAM 配置
ssh root@target "grep cert-sudo-check /etc/pam.d/sudo"
# 如果不存在 → 重新部署

# 第4步：验证 agent 转发
ssh -A -i ~/.hermes/certs/my-key user@target "echo \$SSH_AUTH_SOCK"
# 如果为空 → 连接时缺少 -A 参数

# 第5步：验证 agent 中有证书
ssh -A -i ~/.hermes/certs/my-key user@target "ssh-add -L"
# 应显示证书行（包含 cert-v01@openssh.com）

# 第6步：直接测试 cert-sudo-check
ssh -A -i ~/.hermes/certs/my-key user@target "/usr/local/bin/cert-sudo-check && echo PASS || echo FAIL"
# FAIL → 检查 CA 公钥是否匹配
ssh root@target "ssh-keygen -lf /opt/ca_server/data/ca_key.pub" 2>/dev/null
# 与本地证书的 Signing CA 指纹对比
ssh-keygen -L -f ~/.hermes/certs/my-key-cert.pub | grep "Signing CA"
```

### dpkg-divert 冲突

```bash
# 查看当前 diversion 状态
dpkg-divert --list | grep sudo

# 如果冲突：先移除再重试
dpkg-divert --remove /usr/bin/sudo
# 重新运行 deploy-sudo-wrapper.sh
```

### 自解压安装包损坏

```bash
# 错误：安装包已损坏（未找到内嵌数据）

# 确认 grep 版本支持 -a 参数
grep -an "^__ARCHIVE__$" ca-server-install-v2.3.0.sh

# 如果 grep 找不到标记行，可能包已损坏，重新下载
```

## 备份与恢复

### 备份 CA 服务器

```bash
# 备份整个数据目录
tar -czf /backup/ca-server-$(date +%Y%m%d).tar.gz /opt/ca_server/data/

# 备份配置文件
cp /opt/ca_server/config.json /backup/

# 建议备份内容
# - /opt/ca_server/data/ca_key        CA 私钥（最关键！）
# - /opt/ca_server/data/ca_key.pub    CA 公钥
# - /opt/ca_server/data/https_cert.pem HTTPS 证书
# - /opt/ca_server/data/https_key.pem HTTPS 私钥
# - /opt/ca_server/data/client.cert    mTLS 证书
# - /opt/ca_server/data/client.key     mTLS 私钥
# - /opt/ca_server/data/serial.txt    序列号
# - /opt/ca_server/config.json        配置
```

### 恢复 CA 服务器

```bash
# 全新安装后恢复数据
sudo bash ca-server-install-v2.3.0.sh
sudo systemctl stop cert-operator

# 恢复备份
sudo tar -xzf /backup/ca-server-20250101.tar.gz -C /

# 修复权限
sudo chown -R cert-operator:cert-operator /opt/ca_server/data/
sudo chmod 600 /opt/ca_server/data/ca_key
sudo chmod 600 /opt/ca_server/data/https_key.pem
sudo chmod 600 /opt/ca_server/data/client.key

sudo systemctl start cert-operator
```

### 迁移 CA 服务器到新机器

```bash
# 旧机器：备份数据
tar -czf ca-server-backup.tar.gz \
  /opt/ca_server/data/ \
  /opt/ca_server/config.json

# 新机器：安装系统
sudo bash ca-server-install-v2.3.0.sh

# 新机器：停止服务并恢复数据
sudo systemctl stop cert-operator
sudo tar -xzf ca-server-backup.tar.gz -C /
sudo chown -R cert-operator:cert-operator /opt/ca_server/data/
sudo chmod 600 /opt/ca_server/data/ca_key
sudo chmod 600 /opt/ca_server/data/https_key.pem
sudo chmod 600 /opt/ca_server/data/client.key
sudo systemctl start cert-operator

# 验证
cert-operator pubkey
# 确认 CA 公钥指纹与旧机器一致

# 注意：如果新机器 IP 变了，需要更新 SAN 并重新部署客户端证书
cert-operator renew-cert --san "IP:new.ip.address"
scp /opt/ca_server/data/dist/deploy.sh user@client:~/
ssh user@client "bash ~/deploy.sh"
```

## 日志参考

### 正常启动日志

```
cert-operator v2.3.0 — serving on https://0.0.0.0:8443
  CA ready: true
  rate limit: 5/300s
  mTLS: enabled
```

### 错误日志对照

| 日志错误 | 原因 | 处理 |
|----------|------|------|
| `CA key already exists` | 已初始化，不能重复 init | 删除 data/ 或运行 `reset all` |
| `Failed to load config` | config.json 不存在 | 检查配置文件路径 |
| `failed to read client CA cert` | mTLS 证书缺失 | 运行 init 或 `reset client` |
| `TOTP verification failed` | TOTP 验证码错误 | 检查用户 TOTP 同步 |
| `rate limit exceeded` | 频繁请求 | 等待窗口期结束 |

## 安全建议

1. **定期备份 CA 私钥** — CA 私钥是系统的信任锚点
2. **监控 TOTP 尝试** — 异常大量 TOTP 失败可能是暴力破解
3. **证书有效期** — 默认 60 分钟，可根据安全策略调整
4. **使用 mTLS** — 不要在生产环境使用 `--no-mtls`
5. **sudo wrapper 验证** — 部署后检查 `/tmp/.cert-sudo-sock` 是否存在（正常应在 sudo 调用时创建）
6. **SSH agent 管理** — `cert-operator ssh` 自动清理 agent，手动 SSH 时记得清理
