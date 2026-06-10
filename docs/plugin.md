# Hermes 插件

## 概述

`cert-operator-plugin` 是为 Hermes AI 设计的插件，让 AI 能够通过 TOTP + 证书认证方式安全 SSH 到目标服务器。

完整使用手册见 `cert-operator-plugin/USAGE.md`。

插件提供两个工具：

| 工具 | 描述 |
|------|------|
| 🔐 `get_sub_cert` | 工作流第 1 步：获取 TOTP → CA 签发 SSH 证书 → 保存本地 |
| 🔑 `ssh_with_cert` | 工作流第 2 步：用证书 SSH 登录目标服务器 |

## 安装

```bash
tar -xzf cert-operator-plugin-v2.3.0.tar.gz
mkdir -p ~/.hermes/plugins
cp -r cert-operator-plugin ~/.hermes/plugins/
```

重启 Hermes 后，工具自动出现在工具列表中。

需要先部署客户端证书：

```bash
scp root@ca-server:/opt/ca_server/data/dist/deploy.sh ./
bash deploy.sh
```

## 内部行为

`ssh_with_cert` 自动处理：

1. 启动 ssh-agent，加载证书
2. SSH 连接时自动使用 `-A`（agent forwarding）
3. 远程 `sudo -n` 由目标服务器上的 sudo-wrapper 拦截
4. 命令结束后清理 ssh-agent

**`-A` 是必须的**，没有 agent 转发时远程 cert-sudo-check 无法验证证书。

## 参考

完整使用手册（包含错误排查、CLI 回退、全手动操作、目标服务器部署等）见：

```
cert-operator-plugin/USAGE.md
```
