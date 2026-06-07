"""HTTPS client + SSH execution for cert-operator plugin."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import requests


class CertOperatorError(RuntimeError):
    """Base error for cert-operator operations."""


class CertFetchError(CertOperatorError):
    """Failed to fetch certificate from CA server."""


class SSHConnectionError(CertOperatorError):
    """SSH connection or execution failed."""


class CertificateExpiredError(CertOperatorError):
    """The SSH certificate has expired."""


# ---------------------------------------------------------------------------
# get_sub_cert — fetch SSH certificate from CA server via HTTPS
# ---------------------------------------------------------------------------


def get_sub_cert(
    server: str,
    totp_code: str,
    cert_name: str,
    ca_cert_path: str,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    *,
    timeout: int = 30,
) -> dict:
    """Request a signed SSH sub-certificate from the CA server.

    Args:
        server: CA server base URL, e.g. ``https://ca.example.com:8443``.
        totp_code: 6-digit TOTP code from the user's authenticator app.
        cert_name: File-safe name for the certificate identity.
        ca_cert_path: Path to the CA server's HTTPS self-signed certificate
                      (required; SSL verification is never skipped).
        client_cert: Path to mTLS client certificate (optional, but required
                     when server enforces mTLS).
        client_key: Path to mTLS client private key.
        timeout: Request timeout in seconds (default 30).

    Returns:
        ``{success, cert_path, serial, expires_at}``.

    Raises:
        CertFetchError: On any failure (SSL, network, HTTP error, TOTP refusal).
    """

    # ---- Validate TOTP code format early ----
    if not totp_code.isdigit() or len(totp_code) != 6:
        raise CertFetchError(f"TOTP 码格式错误：需要6位数字，收到 {len(totp_code)} 个字符")

    # ---- Validate ca_cert_path ----
    ca_path = Path(ca_cert_path).expanduser()
    if not ca_path.is_file():
        raise CertFetchError(f"CA 证书文件不存在：{ca_cert_path}")

    # ---- Validate mTLS cert files ----
    cert_tuple = None
    if client_cert and client_key:
        client_cert_path = Path(client_cert).expanduser()
        client_key_path = Path(client_key).expanduser()
        if not client_cert_path.is_file():
            raise CertFetchError(f"mTLS 客户端证书不存在：{client_cert}")
        if not client_key_path.is_file():
            raise CertFetchError(f"mTLS 客户端密钥不存在：{client_key}")
        cert_tuple = (str(client_cert_path), str(client_key_path))

    # ---- Prepare output directory ----
    certs_dir = Path.home() / ".hermes" / "certs"
    certs_dir.mkdir(parents=True, exist_ok=True)

    # ---- Send request ----
    url = server.rstrip("/") + "/api/get-cert"
    try:
        resp = requests.post(
            url,
            json={"totp": totp_code},
            verify=str(ca_path),
            cert=cert_tuple,
            timeout=timeout,
        )
    except requests.exceptions.SSLError as exc:
        raise CertFetchError(
            f"SSL 验证失败：无法验证 CA 服务器证书。请确认 {ca_cert_path} 是服务器 "
            f"https_cert.pem 的正确副本。原始错误：{exc}"
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise CertFetchError(f"连接 CA 服务器失败：{exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise CertFetchError(f"请求 CA 服务器超时（{timeout}s）：{exc}") from exc
    except requests.exceptions.RequestException as exc:
        raise CertFetchError(f"HTTPS 请求异常：{exc}") from exc

    # ---- Parse response ----
    try:
        data = resp.json()
    except json.JSONDecodeError:
        raise CertFetchError(f"CA 服务器返回了非 JSON 响应（HTTP {resp.status_code}）")

    if not data.get("success"):
        error_msg = data.get("error", "未知错误")
        # TOTP-specific errors deserve a clearer message
        if "totp" in error_msg.lower():
            raise CertFetchError(f"TOTP 验证失败：{error_msg}")
        raise CertFetchError(f"CA 服务器拒绝请求（HTTP {resp.status_code}）：{error_msg}")

    # ---- Save private key and certificate ----
    priv_key_path = certs_dir / cert_name
    cert_path = certs_dir / f"{cert_name}-cert.pub"

    try:
        priv_key_path.write_text(data["ssh_private_key"])
        priv_key_path.chmod(0o600)
    except OSError as exc:
        raise CertFetchError(f"写入私钥失败（{priv_key_path}）：{exc}") from exc

    try:
        cert_path.write_text(data["ssh_cert"])
        cert_path.chmod(0o644)
    except OSError as exc:
        # Best-effort cleanup of the private key we already wrote
        try:
            priv_key_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise CertFetchError(f"写入证书失败（{cert_path}）：{exc}") from exc

    return {
        "success": True,
        "cert_path": str(priv_key_path),
        "serial": data.get("serial"),
        "expires_at": data.get("expires_at"),
    }


# ---------------------------------------------------------------------------
# ssh_with_cert — connect to a remote host using the SSH certificate
# ---------------------------------------------------------------------------


def ssh_with_cert(
    host: str,
    user: str,
    cert_path: str,
    command: Optional[str] = None,
    port: int = 22,
    host_key: Optional[str] = None,
    expires_at: Optional[str] = None,
    *,
    timeout: int = 15,
) -> dict:
    """SSH into a remote host using a certificate-authenticated connection.

    OpenSSH auto-discovers the certificate file ``<cert_path>-cert.pub``
    sitting next to the private key.  The caller may optionally supply the
    server's host key fingerprint for strict verification.

    Args:
        host: Remote hostname or IP.
        user: SSH login username.
        cert_path: Path to the private key file.
        command: Optional command to execute (runs a login shell when omitted).
        port: SSH port (default 22).
        host_key: Optional host key fingerprint for ``HostKeyAlgorithms``.
        expires_at: ISO-8601 certificate expiry time; checked before connecting.
        timeout: SSH connection timeout in seconds (default 15).

    Returns:
        ``{success, output, exit_code}``.

    Raises:
        CertificateExpiredError: The certificate at *cert_path* has expired.
        SSHConnectionError: SSH command failed.
    """

    priv = Path(cert_path).expanduser()
    cert = Path(str(priv) + "-cert.pub")

    # ---- Certificate existence checks ----
    if not priv.is_file():
        raise SSHConnectionError(f"私钥文件不存在：{priv}")
    if not cert.is_file():
        raise SSHConnectionError(
            f"证书文件不存在：{cert}\n"
            f"请先通过 get_sub_cert 获取证书，确保私钥和证书位于同一目录。"
        )

    # ---- Expiry check ----
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(expires_at)
        except (ValueError, TypeError):
            raise SSHConnectionError(f"无法解析过期时间：{expires_at}")
        if datetime.now(timezone.utc) >= expiry_dt:
            local_expiry = expiry_dt.astimezone()
            raise CertificateExpiredError(
                f"SSH 证书已于 {local_expiry.strftime('%Y-%m-%d %H:%M:%S')} 过期，"
                f"请通过 get_sub_cert 重新获取。"
            )

    # ---- Build SSH command ----
    known_hosts = Path.home() / ".hermes" / "known_hosts"
    ssh_cmd = [
        "ssh",
        "-i", str(priv),
        "-p", str(port),
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", f"ConnectTimeout={timeout}",
    ]
    if host_key:
        ssh_cmd.extend(["-o", f"HostKeyAlgorithms={host_key}"])

    ssh_cmd.append(f"{user}@{host}")
    if command:
        ssh_cmd.append(command)

    # ---- Execute ----
    try:
        result = subprocess.run(
            ssh_cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
        )
    except subprocess.TimeoutExpired:
        raise SSHConnectionError(f"SSH 连接超时（{timeout}s）：{user}@{host}")
    except FileNotFoundError:
        raise SSHConnectionError("ssh 命令未找到，请确认已安装 OpenSSH 客户端。")
    except Exception as exc:
        raise SSHConnectionError(f"SSH 执行异常：{exc}")

    stdout = result.stdout
    stderr = result.stderr
    exit_code = result.returncode

    # Build a human-readable output
    output = stdout
    if stderr and exit_code != 0:
        output += ("\n" if output else "") + stderr

    return {
        "success": exit_code == 0,
        "output": output.rstrip() or "(no output)",
        "exit_code": exit_code,
    }
