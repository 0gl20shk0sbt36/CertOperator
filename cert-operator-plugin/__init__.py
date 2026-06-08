"""
cert-operator plugin — 安全获取子证书并 SSH 连接

与服务端 CA 证书签发服务配合使用。

工作流程：
  1. AI 调用 get_sub_cert(server, totp_code, cert_name, [ca_cert_path])
     → 用户从 TOTP App 获取一次性码，告诉 AI
     → 插件用 HTTPS（自签证书）请求 CA 服务器
     → 服务器验证 TOTP，生成 SSH 密钥对并用 CA 签名
     → 返回 SSH 私钥 + 证书
     → 插件保存私钥到 ~/.hermes/certs/<name>，证书到 <name>-cert.pub
     → 返回私钥路径给 AI

  2. AI 调用 ssh_with_cert(host, user, cert_path, [port, command])
     → SSH 自动发现同目录下的 <cert_path>-cert.pub 证书文件
     → 执行远程命令并返回结果

密钥安全策略：
  - TOTP 码由用户手动输入，仅短暂经过 AI 上下文
  - 插件不在磁盘上持久化 TOTP 码
  - 子证书（私钥+证书）通过 HTTPS 加密传输，保存到本地时权限 600
  - AI 只看到文件路径，看不到私钥内容
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_CERTS_DIR = Path.home() / ".hermes" / "certs"
"""子证书默认保存目录。"""

DEFAULT_TIMEOUT = 30
"""HTTPS 请求超时秒数。"""

DEFAULT_CA_CERT = DEFAULT_CERTS_DIR / "ca-https-cert.pem"
DEFAULT_CLIENT_CERT = DEFAULT_CERTS_DIR / "client.cert"
DEFAULT_CLIENT_KEY = DEFAULT_CERTS_DIR / "client.key"

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _ensure_certs_dir() -> Path:
    """确保子证书目录存在并设置权限。"""
    path = DEFAULT_CERTS_DIR
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _safe_filename(name: str) -> str:
    """清理文件名中的不安全字符。"""
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def _save_ssh_cert(name: str, private_key: str, cert_content: str) -> tuple[str, str]:
    """保存 SSH 私钥和证书到本地，返回 (私钥路径, 证书路径)。

    SSH 的证书发现规则：如果私钥文件是 ~/.hermes/certs/foo，
    那么证书文件必须是 ~/.hermes/certs/foo-cert.pub，
    SSH 会自动使用该证书进行认证。
    """
    certs_dir = _ensure_certs_dir()
    safe_name = _safe_filename(name)

    # 私钥文件（无扩展名）
    key_path = certs_dir / safe_name
    with open(key_path, "w") as f:
        f.write(private_key)
    key_path.chmod(0o600)

    # 证书文件（<私钥名>-cert.pub，SSH 自动发现规则）
    cert_path = certs_dir / f"{safe_name}-cert.pub"
    with open(cert_path, "w") as f:
        f.write(cert_content)
    cert_path.chmod(0o644)

    logger.info("SSH 私钥已保存: %s", key_path)
    logger.info("SSH 证书已保存: %s", cert_path)

    return str(key_path), str(cert_path)


def _request_cert(
    server: str,
    totp_code: str,
    ca_cert_path: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    group_name: Optional[str] = None,
    user_name: Optional[str] = None,
) -> dict[str, Any]:
    """通过 HTTPS 请求 CA 服务器获取 SSH 子证书。

    Args:
        server: CA 服务器地址，如 'https://ca.example.com:8443'
        totp_code: 用户输入的 TOTP 一次性码
        ca_cert_path: 自签 CA 证书路径（用于验证服务器），为 None 则跳过验证
        client_cert: mTLS 客户端证书路径（可选）
        client_key: mTLS 客户端密钥路径（可选）

    Returns:
        服务器返回的 JSON 响应，包含 ssh_private_key / ssh_cert 等字段

    Raises:
        requests.RequestException: 网络错误
        ValueError: 服务器返回错误或格式异常
    """
    url = f"{server.rstrip('/')}/api/get-cert"

    payload = {"totp": totp_code}
    if group_name:
        payload["group"] = group_name
    if user_name:
        payload["user"] = user_name
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "hermes-cert-operator/1.0",
    }

    # 可选：额外 API Key 认证
    api_key = os.environ.get("CERT_OPERATOR_API_KEY", "")
    if api_key:
        headers["X-API-Key"] = api_key

    # SSL 验证配置：传入 CA 证书路径则启用验证，否则使用默认路径
    verify = ca_cert_path or str(DEFAULT_CA_CERT)

    # mTLS 客户端证书：使用传入或默认路径
    client_cert = client_cert or str(DEFAULT_CLIENT_CERT)
    client_key = client_key or str(DEFAULT_CLIENT_KEY)
    cert = (client_cert, client_key)

    logger.info("请求子证书: %s (verify=%s, mtls=%s)", url, verify, bool(cert))

    resp = requests.post(
        url,
        json=payload,
        headers=headers,
        verify=verify,
        cert=cert,
        timeout=DEFAULT_TIMEOUT,
    )

    resp.raise_for_status()

    data = resp.json()

    if not isinstance(data, dict):
        raise ValueError(f"服务器返回格式异常: {resp.text[:500]}")

    if data.get("error"):
        raise ValueError(f"服务器返回错误: {data['error']}")

    return data


def _run_ssh(
    host: str,
    user: str,
    cert_path: str,
    port: int = 22,
    command: Optional[str] = None,
) -> dict[str, Any]:
    """用子证书执行 SSH 连接。

    SSH 自动发现规则：如果私钥文件是 /path/to/foo，
    则 SSH 会自动寻找 /path/to/foo-cert.pub 作为证书文件。

    Args:
        host: 目标服务器地址
        user: SSH 用户名
        cert_path: SSH 私钥路径（SSH 自动使用同目录下 -cert.pub 证书）
        port: SSH 端口（默认 22）
        command: 要执行的远程命令（为空则生成 SSH 命令字符串）

    Returns:
        包含执行结果的 dict: {success, output, exit_code, ...}
    """
    key_file = Path(cert_path)

    if not key_file.exists():
        return {"success": False, "output": f"私钥文件不存在: {cert_path}", "exit_code": -1}

    # 检查证书文件是否存在
    cert_file = key_file.with_name(f"{key_file.name}-cert.pub")
    has_cert = cert_file.exists()

    # 确保证书权限正确
    key_file.chmod(0o600)

    ssh_cmd = [
        "ssh",
        "-i", str(key_file),
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={DEFAULT_CERTS_DIR}/known_hosts",
        "-o", "ConnectTimeout=15",
    ]

    # 如果证书存在，SSH 会自动使用它（因为命名约定是 <key>-cert.pub）
    target = f"{user}@{host}"

    if command:
        ssh_cmd.extend([target, command])
        try:
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = (result.stdout + result.stderr).strip()
            return {
                "success": result.returncode == 0,
                "output": output or "(无输出)",
                "exit_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "output": "SSH 连接超时", "exit_code": -1}
        except FileNotFoundError:
            return {"success": False, "output": "未找到 ssh 命令，请安装 OpenSSH Client", "exit_code": -1}
        except Exception as e:
            return {"success": False, "output": f"SSH 执行失败: {type(e).__name__}: {e}", "exit_code": -1}
    else:
        cmd_str = " ".join(str(x) for x in ssh_cmd) + f" {target}"
        return {
            "success": True,
            "output": f"交互式 SSH 命令已生成，请手动执行:\n  {cmd_str}",
            "exit_code": 0,
            "command": cmd_str,
            "cert_auto_discovered": has_cert,
        }


# ---------------------------------------------------------------------------
# 工具 handlers
# ---------------------------------------------------------------------------

SCHEMA_GET_SUB_CERT = {
    "name": "get_sub_cert",
    "description": "从目标设备上的 CA 服务器获取 SSH 子证书（CA 服务端运行在被连接设备上，端口 8443）。"
    "需要用户先从 TOTP 认证器 App "
    "（如 Google Authenticator）获取当前 6 位一次性验证码。"
    "服务器验证 TOTP 后签发 SSH 子证书，"
    "通过 HTTPS（支持自签证书 + mTLS 双向验证）加密传输到本地。",
    "parameters": {
        "type": "object",
        "properties": {
            "server": {
                "type": "string",
                "description": "目标设备 CA 服务器地址，如 'https://121.196.206.66:8443'",
            },
            "totp_code": {
                "type": "string",
                "description": "用户从 TOTP App 获取的当前 6 位一次性验证码",
            },
            "cert_name": {
                "type": "string",
                "description": "证书标识名称（用于本地文件名），如 'cloud-server'",
            },
            "ca_cert_path": {
                "type": "string",
                "description": "自签 CA 的 HTTPS 证书路径，默认 ~/.hermes/certs/ca-https-cert.pem",
            },
            "client_cert": {
                "type": "string",
                "description": "mTLS 客户端证书路径，如 ~/.hermes/certs/client.cert",
            },
            "client_key": {
                "type": "string",
                "description": "mTLS 客户端密钥路径，如 ~/.hermes/certs/client.key",
            },
            "group_name": {
                "type": "string",
                "description": "组名（不传则使用 default 组，需要先配置 default 组的 TOTP 和允许用户）",
            },
            "user_name": {
                "type": "string",
                "description": "要登录的 SSH 用户名（不传则证书包含组内所有允许用户）",
            },
        },
        "required": ["server", "totp_code", "cert_name"],
    },
}


def _handle_get_sub_cert(
    server: str,
    totp_code: str,
    cert_name: str,
    ca_cert_path: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    group_name: Optional[str] = None,
    user_name: Optional[str] = None,
) -> str:
    """Handler: 获取 SSH 子证书。"""
    try:
        data = _request_cert(server, totp_code, ca_cert_path, client_cert, client_key, group_name, user_name)

        # 从服务器响应中提取 SSH 私钥和证书
        # 服务端返回格式:
        #   { ssh_private_key: "...PEM...", ssh_cert: "...", serial: N, expires_at: "..." }
        ssh_private_key = data.get("ssh_private_key", "")
        ssh_cert = data.get("ssh_cert", "")

        if not ssh_private_key:
            return json.dumps({
                "success": False,
                "error": "服务器响应中未包含 SSH 私钥。"
                f"收到字段: {list(data.keys())}",
            }, ensure_ascii=False)

        if not ssh_cert:
            return json.dumps({
                "success": False,
                "error": "服务器响应中未包含 SSH 证书。"
                f"收到字段: {list(data.keys())}",
            }, ensure_ascii=False)

        # 保存私钥和证书到本地
        key_path, cert_path = _save_ssh_cert(cert_name, ssh_private_key, ssh_cert)

        result = {
            "success": True,
            "cert_path": key_path,
            "cert_name": cert_name,
            "message": (
                f"✅ SSH 子证书已获取并保存\n"
                f"   私钥: {key_path}\n"
                f"   证书: {cert_path}\n"
                f"   SSH 会自动使用 <私钥名>-cert.pub 进行认证\n\n"
                f"现在可以使用 ssh_with_cert 工具 SSH 到目标服务器"
            ),
        }

        # 附加信息
        for field in ("serial", "expires_at"):
            if field in data:
                result[field] = data[field]

        return json.dumps(result, ensure_ascii=False)

    except requests.exceptions.SSLError as e:
        msg = str(e)
        hint = (
            "如果服务器使用自签证书，请传入 ca_cert_path 参数"
        )
        if "hostname" in msg.lower() or "match" in msg.lower():
            hint = (
                "服务器证书 SAN 不匹配当前地址 — 需要在服务器上更新 HTTPS 证书：\n"
                "  1. 编辑 config.yaml，在 server.san 中加入 IP:121.196.206.66 等地址\n"
                "  2. 运行 python3 ca_server.py renew-cert（不碰 CA 密钥）\n"
                "  3. 重启服务 sudo systemctl restart cert-operator"
            )
        return json.dumps({
            "success": False,
            "error": f"SSL 验证失败: {msg}\n{hint}",
        }, ensure_ascii=False)
    except requests.exceptions.ConnectionError as e:
        return json.dumps({
            "success": False,
            "error": f"无法连接到服务器: {e}\n请检查 server 地址和网络",
        }, ensure_ascii=False)
    except requests.exceptions.Timeout:
        return json.dumps({
            "success": False,
            "error": f"请求超时（{DEFAULT_TIMEOUT} 秒）",
        }, ensure_ascii=False)
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        try:
            detail = e.response.json().get("error", str(e))
        except Exception:
            detail = str(e)
        return json.dumps({
            "success": False,
            "error": f"HTTP {status}: {detail}",
        }, ensure_ascii=False)
    except Exception as e:
        logger.exception("get_sub_cert 失败")
        return json.dumps({
            "success": False,
            "error": f"获取子证书失败: {type(e).__name__}: {e}",
        }, ensure_ascii=False)


# ---------------------------------------------------------------------------

SCHEMA_SSH_WITH_CERT = {
    "name": "ssh_with_cert",
    "description": "用 get_sub_cert 获取的 SSH 子证书连接到目标服务器执行命令。"
    "如果私钥同目录下有 <私钥名>-cert.pub 证书文件，SSH 会自动使用证书认证。",
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "目标服务器主机名或 IP",
            },
            "user": {
                "type": "string",
                "description": "SSH 用户名",
            },
            "cert_path": {
                "type": "string",
                "description": "SSH 私钥路径（get_sub_cert 返回的 cert_path），SSH 会自动使用同目录下的证书",
            },
            "command": {
                "type": "string",
                "description": "要执行的远程命令。为空则只生成 SSH 连接命令",
            },
            "port": {
                "type": "integer",
                "description": "SSH 端口（默认 22）",
                "default": 22,
            },
        },
        "required": ["host", "user", "cert_path"],
    },
}


def _handle_ssh_with_cert(
    host: str,
    user: str,
    cert_path: str,
    command: Optional[str] = None,
    port: int = 22,
) -> str:
    """Handler: 用子证书 SSH 执行命令。"""
    try:
        result = _run_ssh(host, user, cert_path, port, command)
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as e:
        logger.exception("ssh_with_cert 失败")
        return json.dumps({
            "success": False,
            "output": f"SSH 执行失败: {type(e).__name__}: {e}",
            "exit_code": -1,
        }, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 插件注册
# ---------------------------------------------------------------------------


def register(ctx) -> None:
    """注册 cert-operator 插件的两个工具。"""
    ctx.register_tool(
        name="get_sub_cert",
        toolset="custom",
        schema=SCHEMA_GET_SUB_CERT,
        handler=_handle_get_sub_cert,
        description="🔐 通过 TOTP 从 CA 服务器获取 SSH 子证书",
        emoji="🔐",
    )

    ctx.register_tool(
        name="ssh_with_cert",
        toolset="custom",
        schema=SCHEMA_SSH_WITH_CERT,
        handler=_handle_ssh_with_cert,
        description="🔑 用 SSH 子证书连接服务器执行命令",
        emoji="🔑",
    )
