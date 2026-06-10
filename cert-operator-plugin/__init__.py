"""
cert-operator plugin — 安全获取 SSH 子证书并连接目标服务器

工作流程:
  1. AI 调用 get_sub_cert(server, totp_code, cert_name, ...)
     → 用户从 TOTP App 获取一次性码
     → 插件用 HTTPS + mTLS 请求 CA 服务器
     → 服务器验证 TOTP，签发 SSH 子证书
     → 插件保存私钥到 ~/.hermes/certs/<name>，证书到 <name>-cert.pub
     → AI 看到证书保存路径

  2. AI 调用 ssh_with_cert(host, user, cert_path, ...)
     → SSH 自动发现同目录下的证书文件
     → 执行远程命令并返回结果

CA 服务器兼容: v1 (Python) / v2 (Go)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_CERTS_DIR = Path.home() / ".hermes" / "certs"
DEFAULT_TIMEOUT = 30
DEFAULT_CA_CERT = DEFAULT_CERTS_DIR / "ca-https-cert.pem"
DEFAULT_CLIENT_CERT = DEFAULT_CERTS_DIR / "client.cert"
DEFAULT_CLIENT_KEY = DEFAULT_CERTS_DIR / "client.key"
PLUGIN_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# HTTP 请求库：优先用 requests，回退到 urllib
# ---------------------------------------------------------------------------

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

if not HAS_REQUESTS:
    try:
        import urllib.request as _urllib_request
        import urllib.error as _urllib_error
        import ssl as _ssl
        HAS_URLLIB = True
    except ImportError:
        HAS_URLLIB = False
else:
    HAS_URLLIB = False

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _ensure_certs_dir() -> Path:
    path = DEFAULT_CERTS_DIR
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _safe_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def _save_ssh_cert(name: str, private_key: str, cert_content: str) -> tuple[str, str]:
    certs_dir = _ensure_certs_dir()
    safe_name = _safe_filename(name)
    key_path = certs_dir / safe_name
    key_path.write_text(private_key)
    key_path.chmod(0o600)
    cert_path = certs_dir / f"{safe_name}-cert.pub"
    cert_path.write_text(cert_content)
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
    url = f"{server.rstrip('/')}/api/get-cert"
    payload = {"totp": totp_code}
    if group_name:
        payload["group"] = group_name
    if user_name:
        payload["user"] = user_name

    ca_path = ca_cert_path or str(DEFAULT_CA_CERT)
    cc = client_cert or str(DEFAULT_CLIENT_CERT)
    ck = client_key or str(DEFAULT_CLIENT_KEY)

    if HAS_REQUESTS:
        return _request_cert_requests(url, payload, ca_path, cc, ck)
    elif HAS_URLLIB:
        return _request_cert_urllib(url, payload, ca_path, cc, ck)
    else:
        raise RuntimeError("需要 requests 或标准 urllib 支持")


def _request_cert_requests(
    url: str, payload: dict, ca_path: str, cc: str, ck: str
) -> dict[str, Any]:
    import requests
    headers = {"User-Agent": f"hermes-cert-operator/{PLUGIN_VERSION}"}
    resp = requests.post(
        url, json=payload, headers=headers,
        verify=ca_path, cert=(cc, ck),
        timeout=DEFAULT_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError(f"服务器返回格式异常: {resp.text[:500]}")
    if data.get("error"):
        raise ValueError(f"服务器返回错误: {data['error']}")
    return data


def _request_cert_urllib(
    url: str, payload: dict, ca_path: str, cc: str, ck: str
) -> dict[str, Any]:
    import ssl
    import urllib.request
    import urllib.error

    ctx = ssl.create_default_context(cafile=ca_path)
    # mTLS
    ctx.load_cert_chain(cc, ck)

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"hermes-cert-operator/{PLUGIN_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=DEFAULT_TIMEOUT) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        result = json.loads(e.read().decode())
        if result.get("error"):
            raise ValueError(f"服务器返回错误: {result['error']}")
        raise

    if not isinstance(result, dict):
        raise ValueError(f"服务器返回格式异常")
    if result.get("error"):
        raise ValueError(f"服务器返回错误: {result['error']}")
    return result


def _run_ssh(
    host: str, user: str, cert_path: str,
    port: int = 22, command: Optional[str] = None,
) -> dict[str, Any]:
    key_file = Path(cert_path)
    if not key_file.exists():
        return {"success": False, "output": f"私钥文件不存在: {cert_path}", "exit_code": -1}

    cert_file = key_file.with_name(f"{key_file.name}-cert.pub")
    has_cert = cert_file.exists()
    key_file.chmod(0o600)

    ssh_cmd = [
        "ssh", "-i", str(key_file),
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={DEFAULT_CERTS_DIR}/known_hosts",
        "-o", "ConnectTimeout=15",
    ]
    target = f"{user}@{host}"

    if command:
        ssh_cmd.extend([target, command])
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)
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
            "output": f"交互式 SSH 命令已生成:\n  {cmd_str}",
            "exit_code": 0,
            "command": cmd_str,
            "cert_auto_discovered": has_cert,
        }


# ---------------------------------------------------------------------------
# 工具 schemas & handlers
# ---------------------------------------------------------------------------

SCHEMA_GET_SUB_CERT = {
    "name": "get_sub_cert",
    "description": (
        "从 CA 服务器获取 SSH 子证书。"
        "需要用户先从 TOTP 认证器 App 获取当前 6 位验证码。"
        "服务器验证 TOTP 后签发 SSH 子证书，"
        "通过 HTTPS（支持自签证书 + mTLS）加密传输。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "server": {
                "type": "string",
                "description": "CA 服务器地址，如 'https://121.196.206.66:8443'",
            },
            "totp_code": {
                "type": "string",
                "description": "用户从 TOTP App 获取的当前 6 位验证码",
            },
            "cert_name": {
                "type": "string",
                "description": "证书标识（本地文件名），如 'cloud-server'",
            },
            "ca_cert_path": {
                "type": "string",
                "description": "CA HTTPS 证书路径，默认 ~/.hermes/certs/ca-https-cert.pem",
            },
            "client_cert": {
                "type": "string",
                "description": "mTLS 客户端证书路径",
            },
            "client_key": {
                "type": "string",
                "description": "mTLS 客户端密钥路径",
            },
            "group_name": {
                "type": "string",
                "description": "组名（默认使用 default 组）",
            },
            "user_name": {
                "type": "string",
                "description": "SSH 用户名",
            },
        },
        "required": ["server", "totp_code", "cert_name"],
    },
}

SCHEMA_SSH_WITH_CERT = {
    "name": "ssh_with_cert",
    "description": (
        "用 SSH 子证书连接到目标服务器执行命令。"
        "SSH 自动发现 <私钥名>-cert.pub 证书文件。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "目标服务器 IP 或主机名",
            },
            "user": {
                "type": "string",
                "description": "SSH 用户名",
            },
            "cert_path": {
                "type": "string",
                "description": "SSH 私钥路径（get_sub_cert 返回的 cert_path）",
            },
            "command": {
                "type": "string",
                "description": "要执行的远程命令（为空则生成 SSH 命令）",
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
    try:
        data = _request_cert(server, totp_code, ca_cert_path, client_cert, client_key, group_name, user_name)
        ssh_private_key = data.get("ssh_private_key", "")
        ssh_cert = data.get("ssh_cert", "")
        if not ssh_private_key:
            return json.dumps({"success": False, "error": "服务器响应中未包含 SSH 私钥"}, ensure_ascii=False)
        if not ssh_cert:
            return json.dumps({"success": False, "error": "服务器响应中未包含 SSH 证书"}, ensure_ascii=False)

        key_path, cert_path = _save_ssh_cert(cert_name, ssh_private_key, ssh_cert)
        result = {
            "success": True,
            "cert_path": key_path,
            "cert_name": cert_name,
            "message": (
                f"✅ SSH 子证书已获取\n"
                f"   私钥: {key_path}\n"
                f"   证书: {cert_path}\n"
                f"   SSH 会自动使用同目录证书\n\n"
                f"现在可以使用 ssh_with_cert 工具 SSH 到目标服务器"
            ),
        }
        for field in ("serial", "expires_at"):
            if field in data:
                result[field] = data[field]
        return json.dumps(result, ensure_ascii=False)

    except Exception as e:
        logger.exception("get_sub_cert 失败")
        msg = str(e)
        hint = ""
        if "SSL" in type(e).__name__ or "ssl" in msg.lower():
            hint = " — 请确认 ca_cert_path 正确"
        if "Connection" in type(e).__name__:
            hint = " — 请检查服务器地址和网络"
        return json.dumps({"success": False, "error": f"{msg}{hint}"}, ensure_ascii=False)


def _handle_ssh_with_cert(
    host: str,
    user: str,
    cert_path: str,
    command: Optional[str] = None,
    port: int = 22,
) -> str:
    try:
        result = _run_ssh(host, user, cert_path, port, command)
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as e:
        logger.exception("ssh_with_cert 失败")
        return json.dumps({"success": False, "output": f"SSH 执行失败: {e}", "exit_code": -1}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 插件注册
# ---------------------------------------------------------------------------


def register(ctx) -> None:
    """注册 cert-operator 的两个工具。"""
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
