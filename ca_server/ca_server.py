#!/usr/bin/env python3
"""CA Server for cert-operator — TOTP-gated SSH certificate authority.

Subcommands::

    ca_server.py init                    # ① 一键初始化
    ca_server.py totp                    # ② 配置 TOTP
    ca_server.py totp --verify           # ③ 验证 TOTP 码
    ca_server.py totp --regenerate       # ④ 重新生成 Secret
    ca_server.py serve                   # ⑤ 启动 HTTPS 服务
    ca_server.py serve --debug           # ⑥ 调试模式
    ca_server.py serve --host 0.0.0.0 --port 8443  # ⑦ 指定地址
    ca_server.py pubkey                  # ⑧ 显示 CA 公钥

All certificate issuance goes through TOTP verification — there is no
offline / bypass mode.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional

import pyotp
import yaml

# ---------------------------------------------------------------------------
# Paths (relative to this script's directory)
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = BASE_DIR / "config.yaml"

CA_KEY = DATA_DIR / "ca_key"
CA_KEY_PUB = DATA_DIR / "ca_key.pub"
HTTPS_KEY = DATA_DIR / "https_key.pem"
HTTPS_CERT = DATA_DIR / "https_cert.pem"
CLIENT_KEY = DATA_DIR / "client.key"
CLIENT_CERT = DATA_DIR / "client.cert"
TOTP_SECRET_FILE = DATA_DIR / "totp_secret.txt"
SERIAL_FILE = DATA_DIR / "serial.txt"

DIST_DIR = BASE_DIR / "dist"


def load_config() -> dict:
    if not CONFIG_PATH.is_file():
        print(f"❌ 配置文件不存在：{CONFIG_PATH}，请先运行 init")
        sys.exit(1)
    return yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))


def save_config(cfg: dict) -> None:
    CONFIG_PATH.write_text(yaml.safe_dump(cfg, allow_unicode=True, default_flow_style=False), encoding="utf-8")


def ensure_data_dir() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# serial counter
# ---------------------------------------------------------------------------

def _read_serial() -> int:
    if SERIAL_FILE.is_file():
        return int(SERIAL_FILE.read_text().strip())
    return 0


def _write_serial(n: int) -> None:
    SERIAL_FILE.write_text(str(n))


def _next_serial() -> int:
    """Atomically increment and return the next certificate serial number."""
    current = _read_serial()
    nxt = current + 1
    _write_serial(nxt)
    return nxt


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def _cmd_init() -> None:
    ensure_data_dir()

    # Validate no existing keys
    if CA_KEY.is_file():
        print("⚠️  CA 密钥已存在，如需重新初始化请先删除 data/ 目录")
        sys.exit(1)

    cfg = load_config()
    key_type = cfg.get("ca", {}).get("key_type", "ed25519")

    # ---- 1. Generate CA key pair ----
    print(f"🔨 生成 CA 密钥对（{key_type}）...")
    subprocess.run(
        ["ssh-keygen", "-t", key_type, "-f", str(CA_KEY),
         "-N", "", "-C", "ca-server@cert-operator"],
        check=True, capture_output=True,
    )
    CA_KEY.chmod(0o600)
    CA_KEY_PUB.chmod(0o644)
    print(f"   ✅ CA 私钥: {CA_KEY}")
    print(f"   ✅ CA 公钥: {CA_KEY_PUB}")

    # ---- 2. Generate HTTPS self-signed certificate ----
    print("🔨 生成 HTTPS 自签证书...")
    subprocess.run(
        [
            "openssl", "req", "-x509",
            "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-days", "3650",
            "-nodes",
            "-keyout", str(HTTPS_KEY),
            "-out", str(HTTPS_CERT),
            "-subj", "/CN=CertOperator/O=CertOperator/C=CN",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True, capture_output=True,
    )
    HTTPS_KEY.chmod(0o600)
    HTTPS_CERT.chmod(0o644)
    print(f"   ✅ HTTPS 私钥: {HTTPS_KEY}")
    print(f"   ✅ HTTPS 证书: {HTTPS_CERT}")

    # ---- 3. Init serial counter ----
    _write_serial(0)
    print(f"   ✅ 序列号计数器: {SERIAL_FILE} (初始值 0)")

    # ---- 4. Generate mTLS client certificate ----
    _generate_client_cert()

    # ---- 5. Generate deploy script ----
    _generate_deploy_script()

    # ---- 6. Target server configuration guide ----
    print("\n" + "=" * 60)
    print("📋 目标服务器配置指南")
    print("=" * 60)
    print()
    print("将 CA 公钥部署到目标服务器：")
    print()
    ca_pub = CA_KEY_PUB.read_text().strip()
    print(f"  # 1. 复制 CA 公钥")
    print(f"  scp {CA_KEY_PUB} root@target-server:/etc/ssh/ca_key.pub")
    print()
    print(f"  # 2. 编辑 /etc/ssh/sshd_config，添加：")
    print(f"  TrustedUserCAKeys /etc/ssh/ca_key.pub")
    print()
    print(f"  # 3. 重启 SSH 服务")
    print(f"  sudo systemctl restart sshd")
    print()
    print(f"  # 4. 验证配置")
    print(f"  sudo sshd -T | grep trust")
    print()
    print("-" * 60)
    print("🔑 CA 公钥内容：")
    print(ca_pub)
    print("-" * 60)
    print()
    print("📦 客户端部署包（包含三个文件，一次传输）：")
    print(f"  scp {DIST_DIR/'deploy.sh'} user@client:~")
    print(f"  客户端运行: bash ~/deploy.sh")
    print()
    print("下一步：")
    print("  ca_server.py totp          # 配置 TOTP")
    print("  ca_server.py serve         # 启动服务（mTLS 双向验证）")


# ---------------------------------------------------------------------------
# client certificate + deploy script
# ---------------------------------------------------------------------------


def _generate_client_cert() -> None:
    """Generate mTLS client certificate key pair."""
    print("🔨 生成客户端 mTLS 证书...")
    # Generate EC private key
    subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "prime256v1",
         "-out", str(CLIENT_KEY)],
        check=True, capture_output=True,
    )
    CLIENT_KEY.chmod(0o600)
    # Generate self-signed client cert
    subprocess.run(
        ["openssl", "req", "-new", "-x509",
         "-key", str(CLIENT_KEY),
         "-out", str(CLIENT_CERT),
         "-days", "3650",
         "-subj", "/CN=CertOperatorClient/O=CertOperator/C=CN"],
        check=True, capture_output=True,
    )
    CLIENT_CERT.chmod(0o644)
    print(f"   ✅ 客户端密钥: {CLIENT_KEY}")
    print(f"   ✅ 客户端证书: {CLIENT_CERT}")


def _generate_deploy_script() -> None:
    """Generate dist/deploy.sh — self-extracting client deployment script."""
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    https_cert_b64 = base64.b64encode(HTTPS_CERT.read_bytes()).decode()
    client_cert_b64 = base64.b64encode(CLIENT_CERT.read_bytes()).decode()
    client_key_b64 = base64.b64encode(CLIENT_KEY.read_bytes()).decode()

    script = r"""#!/bin/bash
# cert-operator 客户端部署包 — 由 ca_server.py init 自动生成
set -euo pipefail

CERT_DIR="${HOME}/.hermes/certs"
mkdir -p "$CERT_DIR"

echo "📦 部署客户端证书到 $CERT_DIR"

# ---- ca-https-cert.pem (644) ----
cat > "$CERT_DIR/ca-https-cert.pem" << 'CERT_EOF'
""" + HTTPS_CERT.read_text().strip() + """
CERT_EOF
chmod 644 "$CERT_DIR/ca-https-cert.pem"

# ---- client.cert (644) ----
cat > "$CERT_DIR/client.cert" << 'CERT_EOF'
""" + CLIENT_CERT.read_text().strip() + """
CERT_EOF
chmod 644 "$CERT_DIR/client.cert"

# ---- client.key (600) ----
cat > "$CERT_DIR/client.key" << 'CERT_EOF'
""" + CLIENT_KEY.read_text().strip() + """
CERT_EOF
chmod 600 "$CERT_DIR/client.key"

echo ""
echo "✅ 部署完成！"
echo "   HTTPS 证书: $CERT_DIR/ca-https-cert.pem"
echo "   客户端证书: $CERT_DIR/client.cert"
echo "   客户端密钥: $CERT_DIR/client.key"
echo ""
echo "运行 get_sub_cert 所需参数:"
echo "  ca_cert_path=$CERT_DIR/ca-https-cert.pem"
echo "  client_cert=$CERT_DIR/client.cert"
echo "  client_key=$CERT_DIR/client.key"
"""

    deploy_path = DIST_DIR / "deploy.sh"
    deploy_path.write_text(script)
    deploy_path.chmod(0o755)
    print(f"   ✅ 部署脚本: {deploy_path} ({deploy_path.stat().st_size} bytes)")


# ---------------------------------------------------------------------------
# totp
# ---------------------------------------------------------------------------


def _read_totp_secret(_cfg: Optional[dict] = None) -> Optional[str]:
    """Read TOTP secret from data/totp_secret.txt only."""
    if TOTP_SECRET_FILE.is_file():
        return TOTP_SECRET_FILE.read_text().strip()
    return None


def _write_totp_secret(secret: str, _cfg: Optional[dict] = None) -> None:
    """Write TOTP secret to data/totp_secret.txt only."""
    TOTP_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOTP_SECRET_FILE.write_text(secret)
    TOTP_SECRET_FILE.chmod(0o600)


def _cmd_totp(args) -> None:
    ensure_data_dir()
    cfg = load_config()
    issuer = cfg.get("totp", {}).get("issuer", "CertOperator")
    account = cfg.get("totp", {}).get("account", "admin")

    if args.regenerate:
        secret = pyotp.random_base32()
        _write_totp_secret(secret)
        print(f"🔄 已重新生成 TOTP Secret")
    else:
        secret = _read_totp_secret()
        if not secret:
            secret = pyotp.random_base32()
            _write_totp_secret(secret)
            print(f"🔐 已生成新的 TOTP Secret")
        else:
            print(f"🔐 当前 TOTP 配置")

    # ---- Display ----
    print()
    print(f"  Issuer : {issuer}")
    print(f"  Account: {account}")
    print(f"  Secret : {secret}")
    print()

    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=account, issuer_name=issuer)

    # ---- Try QR code generation ----
    try:
        import qrcode  # type: ignore
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(uri)
        qr.make(fit=True)

        # Terminal QR code (ANSI background colors)
        matrix = qr.get_matrix()
        print("📱 终端二维码（请用白色背景终端扫码）：")
        for row in matrix:
            line = ''.join(
                '\033[40m  \033[0m' if cell else '\033[47m  \033[0m'
                for cell in row
            )
            print(line)

        # Save PNG
        img = qr.make_image(fill_color="black", back_color="white")
        qr_path = DATA_DIR / "totp_qrcode.png"
        img.save(str(qr_path))
        print(f"   📄 图片已保存: {qr_path}")
    except ImportError:
        print("💡 安装 qrcode 库可显示二维码: uv pip install qrcode[pil]")
        print(f"   扫码 URI: {uri}")

    print()

    if args.verify:
        totp = pyotp.TOTP(secret)
        print(f"✅ 当前验证码: {totp.now()}")
        print("   请与手机 App 显示的验证码对比确认")
    else:
        print("💡 运行 ca_server.py totp --verify 验证当前 TOTP 码")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def _cmd_serve(args) -> None:
    """Start the Flask HTTPS API server."""

    cfg = load_config()

    # ---- Validate preconditions ----
    if not CA_KEY.is_file():
        print("❌ CA 密钥不存在，请先运行: ca_server.py init")
        sys.exit(1)
    if not HTTPS_KEY.is_file() or not HTTPS_CERT.is_file():
        print("❌ HTTPS 证书不存在，请先运行: ca_server.py init")
        sys.exit(1)

    secret = _read_totp_secret()
    if not secret:
        print("❌ TOTP Secret 未配置，请先运行: ca_server.py totp")
        sys.exit(1)

    # ---- Server config ----
    host = args.host or cfg.get("server", {}).get("host", "0.0.0.0")
    port = args.port or cfg.get("server", {}).get("port", 8443)
    debug = args.debug
    no_mtls = args.no_mtls

    # Validate mTLS preconditions
    if not no_mtls:
        if not CLIENT_CERT.is_file():
            print("❌ mTLS 客户端证书不存在，请重新运行: ca_server.py init")
            print("   （或传递 --no-mtls 禁用双向验证）")
            sys.exit(1)
        if not CLIENT_KEY.is_file():
            print("❌ mTLS 客户端密钥不存在，请重新运行: ca_server.py init")
            sys.exit(1)

    key_type = cfg.get("ca", {}).get("key_type", "ed25519")
    validity_hours = cfg.get("ca", {}).get("validity_hours", 1)
    allowed_users = cfg.get("ca", {}).get("allowed_users", "root,yyx,ubuntu")

    max_attempts = cfg.get("rate_limit", {}).get("max_attempts", 5)
    window_seconds = cfg.get("rate_limit", {}).get("window_seconds", 300)

    totp = pyotp.TOTP(secret)

    # ---- Rate limiter ----
    rate_lock = threading.Lock()
    rate_attempts: Dict[str, list] = {}  # remote_addr -> list of timestamps

    def check_rate_limit(addr: str) -> bool:
        """Return True if the request is allowed."""
        now = time.time()
        with rate_lock:
            window_start = now - window_seconds
            # Prune old entries
            if addr in rate_attempts:
                rate_attempts[addr] = [t for t in rate_attempts[addr] if t > window_start]
            else:
                rate_attempts[addr] = []
            if len(rate_attempts[addr]) >= max_attempts:
                return False
            rate_attempts[addr].append(now)
            return True

    # ---- Flask app ----
    try:
        from flask import Flask, jsonify, request  # type: ignore
    except ImportError:
        print("❌ 缺少 Flask 依赖，请先安装: pip install flask pyotp pyyaml")
        sys.exit(1)

    app = Flask(__name__)

    @app.route("/api/get-cert", methods=["POST"])
    def api_get_cert():
        # Rate limit
        client_addr = request.remote_addr or "unknown"
        if not check_rate_limit(client_addr):
            return jsonify({
                "success": False,
                "error": f"请求过于频繁，请等待 {window_seconds} 秒后重试",
            }), 429

        # Parse body
        body = request.get_json(silent=True)
        if not body or "totp" not in body:
            return jsonify({
                "success": False,
                "error": "请求体中缺少 totp 字段",
            }), 400

        totp_code = str(body["totp"]).strip()

        # Validate format
        if not totp_code.isdigit() or len(totp_code) != 6:
            return jsonify({
                "success": False,
                "error": "TOTP 码格式错误：需要6位数字",
            }), 400

        # Verify TOTP
        if not totp.verify(totp_code, valid_window=1):
            return jsonify({
                "success": False,
                "error": "TOTP 验证失败，请确认验证码正确且未过期",
            }), 401

        # ---- Issue SSH certificate ----
        try:
            result = _issue_cert(key_type, allowed_users, validity_hours)
        except Exception as exc:
            return jsonify({
                "success": False,
                "error": f"签发证书失败：{exc}",
            }), 500

        return jsonify({
            "success": True,
            "ssh_private_key": result["ssh_private_key"],
            "ssh_cert": result["ssh_cert"],
            "serial": result["serial"],
            "expires_at": result["expires_at"],
        })

    @app.route("/api/health", methods=["GET"])
    def api_health():
        return jsonify({
            "status": "ok",
            "totp_configured": True,
            "ca_ready": CA_KEY.is_file() and CA_KEY_PUB.is_file(),
        })

    @app.route("/api/info", methods=["GET"])
    def api_info():
        return jsonify({
            "ca_key_type": key_type,
            "validity_hours": validity_hours,
            "allowed_users": allowed_users,
            "ca_public_key": CA_KEY_PUB.read_text().strip() if CA_KEY_PUB.is_file() else None,
        })

    # ---- Start ----
    print(f"🚀 CA 服务器启动中...")
    print(f"   地址: https://{host}:{port}")
    print(f"   证书有效期: {validity_hours}h")
    print(f"   允许用户: {allowed_users}")
    print(f"   限速: {max_attempts}次/{window_seconds}秒")
    if no_mtls:
        print(f"   mTLS: 已禁用（仅单向验证）")
    else:
        print(f"   mTLS: 已启用（客户端证书验证）")
    if debug:
        print(f"   调试模式: 开启")
    print()

    if no_mtls:
        app.run(host=host, port=port, ssl_context=(str(HTTPS_CERT), str(HTTPS_KEY)),
                threaded=True, debug=debug)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(HTTPS_CERT), str(HTTPS_KEY))
        ctx.load_verify_locations(cafile=str(CLIENT_CERT))
        ctx.verify_mode = ssl.CERT_REQUIRED
        app.run(host=host, port=port, ssl_context=ctx,
                threaded=True, debug=debug)


def _issue_cert(key_type: str, allowed_users: str, validity_hours: int) -> dict:
    """Generate a temporary key pair, sign with CA, return private key + cert."""

    ensure_data_dir()
    serial = _next_serial()

    # 1. Generate temporary key pair
    tmp_key = DATA_DIR / f".tmp_{serial}"
    # "ca-server-user-<serial>" ensures uniqueness; CA comment doesn't propagate to the cert
    subprocess.run(
        ["ssh-keygen", "-t", key_type, "-f", str(tmp_key),
         "-N", "", "-C", f"ca-server-user-{serial}"],
        check=True, capture_output=True, text=True,
    )
    tmp_pub = DATA_DIR / f".tmp_{serial}.pub"

    try:
        # 2. CA sign the temporary public key
        cert_path = str(tmp_key) + "-cert.pub"
        identity = f"cert-{serial}"
        validity = f"+{validity_hours}h"

        subprocess.run(
            [
                "ssh-keygen", "-s", str(CA_KEY),
                "-I", identity,
                "-n", allowed_users,
                "-V", validity,
                "-z", str(serial),
                str(tmp_pub),
            ],
            check=True, capture_output=True, text=True,
        )

        # 3. Read results
        ssh_private_key = tmp_key.read_text()
        ssh_cert = Path(cert_path).read_text()

        # 4. Compute expiry
        expires_dt = datetime.now(timezone.utc) + timedelta(hours=validity_hours)
        expires_at = expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "ssh_private_key": ssh_private_key,
            "ssh_cert": ssh_cert,
            "serial": serial,
            "expires_at": expires_at,
        }
    finally:
        # 5. Cleanup temporary files (server never stores client keys)
        for p in [tmp_key, tmp_pub, Path(cert_path)]:
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# pubkey
# ---------------------------------------------------------------------------


def _cmd_pubkey() -> None:
    if not CA_KEY_PUB.is_file():
        print("❌ CA 公钥不存在，请先运行: ca_server.py init")
        sys.exit(1)

    ca_pub = CA_KEY_PUB.read_text().strip()
    print("🔑 CA 公钥：")
    print("-" * 60)
    print(ca_pub)
    print("-" * 60)
    print()
    print("📋 目标服务器配置命令：")
    print()
    print(f"  # 1. 复制 CA 公钥")
    print(f"  scp {CA_KEY_PUB} root@target-server:/etc/ssh/ca_key.pub")
    print()
    print(f"  # 2. 编辑 /etc/ssh/sshd_config，添加：")
    print(f"  TrustedUserCAKeys /etc/ssh/ca_key.pub")
    print()
    print(f"  # 3. 重启 SSH 服务")
    print(f"  sudo systemctl restart sshd")
    print()
    print(f"  # 4. 验证")
    print(f"  sudo sshd -T | grep trust")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CertOperator CA 服务器 — TOTP-gated SSH 证书签发",
    )
    sub = parser.add_subparsers(dest="command", title="子命令")

    # init
    sub.add_parser("init", help="初始化 CA 密钥对和 HTTPS 自签证书")

    # totp
    p_totp = sub.add_parser("totp", help="配置或管理 TOTP")
    p_totp.add_argument("--verify", action="store_true", help="显示当前 TOTP 验证码")
    p_totp.add_argument("--regenerate", action="store_true", help="重新生成 TOTP Secret")

    # serve
    p_serve = sub.add_parser("serve", help="启动 HTTPS API 服务（默认 mTLS 双向验证）")
    p_serve.add_argument("--debug", action="store_true", help="开启 Flask 调试模式")
    p_serve.add_argument("--host", help="监听地址（覆盖 config.yaml）")
    p_serve.add_argument("--port", type=int, help="监听端口（覆盖 config.yaml）")
    p_serve.add_argument("--no-mtls", action="store_true", help="禁用 mTLS 双向验证（仅单向 HTTPS）")

    # pubkey
    sub.add_parser("pubkey", help="显示 CA 公钥")

    args = parser.parse_args()

    if args.command == "init":
        _cmd_init()
    elif args.command == "totp":
        _cmd_totp(args)
    elif args.command == "serve":
        _cmd_serve(args)
    elif args.command == "pubkey":
        _cmd_pubkey()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
