# 配置参考

## config.json

CA 服务器的配置文件，位于 `/opt/ca_server/config.json`。

### 默认配置

```json
{
  "ca": {
    "key_type": "ed25519",
    "validity_minutes": 60
  },
  "server": {
    "host": "0.0.0.0",
    "port": 8443,
    "san": ""
  },
  "rate_limit": {
    "max_attempts": 5,
    "window_seconds": 300
  },
  "totp": {
    "issuer": "CertOperator",
    "account": "admin"
  }
}
```

### 配置项说明

| 路径 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `ca.key_type` | string | `ed25519` | CA 密钥类型 |
| `ca.validity_minutes` | int | `60` | 默认证书有效期（分钟） |
| `server.host` | string | `0.0.0.0` | API 服务器监听地址 |
| `server.port` | int | `8443` | API 服务器端口 |
| `server.san` | string | `""` | HTTPS 证书 SAN，多值用逗号分隔 |
| `rate_limit.max_attempts` | int | `5` | 时间窗口内最大尝试次数 |
| `rate_limit.window_seconds` | int | `300` | 时间窗口（秒） |
| `totp.issuer` | string | `CertOperator` | TOTP 签发者名称 |
| `totp.account` | string | `admin` | TOTP 账户名称 |

### SAN 配置示例

更新 HTTPS 证书的 SAN 以允许更多地址访问：

```json
{
  "server": {
    "san": "DNS:ca.example.com,IP:192.168.1.100,IP:10.0.0.1"
  }
}
```

修改后运行 `ca-server renew-cert` 重新生成证书。

## 组配置

通过 `ca-server groups config` 命令配置每个组的属性：

| 键 | 值 | 说明 |
|---|-----|------|
| `sudo` | `yes` / `no` | 证书是否包含 sudo 扩展 |
| `frozen` | `yes` / `no` | 是否冻结组（停止签发） |
| `validity-minutes` | 数字 | 证书有效期（分钟） |
| `parent` | 组名 / `none` | 父组（继承用户和扩展） |
| `allowed-users` | 用户名列表 | 逗号分隔的允许用户 |

示例：

```bash
cert-operator groups config devops set sudo yes
cert-operator groups config devops set parent admin
cert-operator groups config devops set validity-minutes 120
```

## 环境变量

| 变量 | 用途 |
|------|------|
| `CA_SERVER_CONFIG` | 指定 config.json 路径（默认当前目录） |
| `CERT_OPERATOR_API_KEY` | 插件 API Key 认证（可选） |
