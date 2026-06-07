"""Schema definitions and handler functions for cert-operator tools."""

from __future__ import annotations

import json
from typing import Any

from .client import (
    CertFetchError,
    CertOperatorError,
    CertificateExpiredError,
    SSHConnectionError,
    get_sub_cert as _get_sub_cert,
    ssh_with_cert as _ssh_with_cert,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool_result(data: Any) -> str:
    """Serialize a successful tool result as a JSON string."""
    return json.dumps(data, ensure_ascii=False, indent=2)


def _tool_error(message: str, **extra: Any) -> str:
    """Serialize a tool error result as a JSON string."""
    payload: dict = {"success": False, "error": message}
    if extra:
        payload.update(extra)
    return json.dumps(payload, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


GET_SUB_CERT_SCHEMA: dict = {
    "name": "get_sub_cert",
    "description": (
        "通过 TOTP 一次性验证码，经 HTTPS + mTLS（双向证书验证）从 CA 服务器获取 "
        "SSH 子证书。需要提前运行 deploy.sh 部署客户端证书。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "server": {
                "type": "string",
                "description": "CA 服务器地址，如 https://ca.example.com:8443",
            },
            "totp_code": {
                "type": "string",
                "description": "6 位 TOTP 一次性验证码（从 Google Authenticator / Authy 查看）",
            },
            "cert_name": {
                "type": "string",
                "description": "证书文件名标识，用于区分不同目标服务器，如 prod-server",
            },
            "ca_cert_path": {
                "type": "string",
                "description": "CA 服务器 HTTPS 自签证书的本地路径（必填，用于 SSL 验证），如 ~/.hermes/certs/ca-https-cert.pem",
            },
            "client_cert": {
                "type": "string",
                "description": "mTLS 客户端证书路径（必填），如 ~/.hermes/certs/client.cert",
            },
            "client_key": {
                "type": "string",
                "description": "mTLS 客户端密钥路径（必填），如 ~/.hermes/certs/client.key",
            },
        },
        "required": ["server", "totp_code", "cert_name", "ca_cert_path", "client_cert", "client_key"],
    },
}

SSH_WITH_CERT_SCHEMA: dict = {
    "name": "ssh_with_cert",
    "description": (
        "使用 SSL 证书登录目标服务器并执行命令。"
        "OpenSSH 自动发现同目录下的 <cert_path>-cert.pub 证书文件。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "目标服务器地址或 IP",
            },
            "user": {
                "type": "string",
                "description": "SSH 登录用户名",
            },
            "cert_path": {
                "type": "string",
                "description": "私钥路径，如 ~/.hermes/certs/prod-server（证书自动发现同目录下的 prod-server-cert.pub）",
            },
            "command": {
                "type": "string",
                "description": "要执行的命令（可选，省略则启动登录 shell）",
            },
            "port": {
                "type": "integer",
                "description": "SSH 端口（默认 22）",
            },
            "host_key": {
                "type": "string",
                "description": "目标服务器 SSH 主机密钥指纹（可选，用于 HostKeyAlgorithms）",
            },
            "expires_at": {
                "type": "string",
                "description": "证书过期时间 ISO 8601 格式（可选，用于连接前检查证书是否过期）",
            },
        },
        "required": ["host", "user", "cert_path"],
    },
}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


def _handle_get_sub_cert(args: dict, **kw: Any) -> str:
    """Handle a ``get_sub_cert`` tool invocation."""
    try:
        result = _get_sub_cert(
            server=str(args["server"]).strip(),
            totp_code=str(args["totp_code"]).strip(),
            cert_name=str(args["cert_name"]).strip(),
            ca_cert_path=str(args["ca_cert_path"]).strip(),
            client_cert=str(args.get("client_cert") or "").strip() or None,
            client_key=str(args.get("client_key") or "").strip() or None,
        )
        return _tool_result(result)
    except CertFetchError as exc:
        return _tool_error(str(exc))
    except Exception as exc:
        return _tool_error(f"get_sub_cert 异常：{type(exc).__name__}: {exc}")


def _handle_ssh_with_cert(args: dict, **kw: Any) -> str:
    """Handle a ``ssh_with_cert`` tool invocation."""
    try:
        result = _ssh_with_cert(
            host=str(args["host"]).strip(),
            user=str(args["user"]).strip(),
            cert_path=str(args["cert_path"]).strip(),
            command=args.get("command"),
            port=int(args.get("port") or 22),
            host_key=args.get("host_key"),
            expires_at=args.get("expires_at"),
        )
        return _tool_result(result)
    except CertificateExpiredError as exc:
        return _tool_error(str(exc), reason="cert_expired")
    except SSHConnectionError as exc:
        return _tool_error(str(exc))
    except Exception as exc:
        return _tool_error(f"ssh_with_cert 异常：{type(exc).__name__}: {exc}")
