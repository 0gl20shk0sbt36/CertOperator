# cert-operator

> TOTP + mTLS 双层认证 SSH 证书签发系统。零信任远程登录，证书扩展控制 sudo 权限。

## 快速开始

```bash
# 服务端 (CA)
wget https://github.com/user/cert-operator/releases/download/v2.0.0/ca-server-v2.0.0-linux-x86_64.tar.gz
tar -xzf ca-server-v2.0.0-linux-x86_64.tar.gz
sudo bash install.sh
sudo systemctl start cert-operator

# 客户端（用来拿证书）
wget https://github.com/user/cert-operator/releases/download/v2.0.0/cert-operator-v2.0.0-linux-x86_64.tar.gz
tar -xzf cert-operator-v2.0.0-linux-x86_64.tar.gz
chmod +x cert-operator
./cert-operator get-cert https://<ca-server>:8443 123456 my-key --group admin
./cert-operator ssh 192.168.1.100 root ~/.hermes/certs/my-key
```

## 架构

```
用户/TOTP App ──(6位码)──▶ Hermes AI ──(HTTPS+mTLS)──▶ CA 服务器 ──(SSH 证书)──▶ 目标服务器
                              │                           │                        │
                           client.cert                 ca_key.pub              ca_key.pub
                           client.key                  https_cert.pem           TrustedUserCAKeys
                           ca-https-cert.pem            client.cert             cert-sudo-check
```

## 组件

| 组件 | 语言 | 位置 | 功能 |
|------|------|------|------|
| **ca-server** | Go | `go/ca-server/` | CA 服务器 (HTTPS + mTLS + TOTP + 证书签发) |
| **cert-operator** | Go | `go/ca-server/cmd/cert-operator/` | 客户端 CLI (拿证书 + SSH) |
| **cert-operator-plugin** | Python | `cert-operator-plugin/` | Hermes AI 插件 (get_sub_cert + ssh_with_cert) |

## 文档

- [架构说明](docs/architecture.md)
- [安装指南](docs/installation.md)
- [客户端使用](docs/client.md)
- [Hermes 插件](docs/plugin.md)
- [配置参考](docs/configuration.md)
- [安全模型](docs/security.md)

## 许可证

MIT
