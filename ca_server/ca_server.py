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
VERSION = "1.0.0"

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
# command hint — auto-detect dev vs production install
# ---------------------------------------------------------------------------

SERVICE_USER = "cert-operator"


def _cmd_hint(subcommand: str) -> str:
    """Return the correct shell command for *subcommand* based on runtime env.

    Development (``python3 ca_server.py``) vs production install
    (``sudo -u cert-operator /opt/ca_server/.venv/bin/python ...``)
    is detected by checking whether ``sys.executable`` is inside a venv.
    """
    import os
    exec_path = sys.executable or "python3"
    script_path = os.path.abspath(__file__)

    if ".venv" in exec_path:
        # Installed via install.sh — hint includes sudo + full path
        return f"sudo -u {SERVICE_USER} {exec_path} {script_path} {subcommand}"
    else:
        # Development — just the basename
        return f"python3 {os.path.basename(script_path)} {subcommand}"


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
    san = cfg.get("server", {}).get("san", "")
    # 始终包含 localhost 作为回退
    san_list = ["DNS:localhost", "IP:127.0.0.1"]
    if san.strip():
        for entry in san.replace(",", " ").split():
            entry = entry.strip()
            if entry:
                san_list.append(entry)
    san_ext = "subjectAltName=" + ",".join(san_list)
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
            "-addext", san_ext,
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

    # ---- 7. Create default group ----
    _ensure_default_group(cfg)


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
    _ensure_default_group(cfg)
    dg = cfg["groups"]["default"]
    issuer = cfg.get("totp", {}).get("issuer", "CertOperator")
    account = cfg.get("totp", {}).get("account", "admin")

    if args.regenerate:
        secret = pyotp.random_base32()
        dg["totp_secret"] = secret
        save_config(cfg)
        print(f"🔄 已重新生成 TOTP Secret（default 组）")
    else:
        secret = dg.get("totp_secret", "")
        if not secret:
            secret = pyotp.random_base32()
            dg["totp_secret"] = secret
            save_config(cfg)
            print(f"🔐 已生成新的 TOTP Secret（default 组）")
        else:
            print(f"🔐 当前 TOTP 配置（default 组）")

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
        print(f"💡 运行 {_cmd_hint('totp --verify')} 验证当前 TOTP 码")


# ---------------------------------------------------------------------------
# serve
# ---------------------------------------------------------------------------


def _cmd_serve(args) -> None:
    """Start the Flask HTTPS API server."""

    cfg = load_config()
    # 迁移旧全局配置到 default 组，必须在预检之前
    _ensure_default_group(cfg)
    cfg = load_config()  # re-read after migration

    # ---- Validate preconditions ----
    if not CA_KEY.is_file():
        print(f"❌ CA 密钥不存在，请先运行: {_cmd_hint('init')}")
        sys.exit(1)
    if not HTTPS_KEY.is_file() or not HTTPS_CERT.is_file():
        print(f"❌ HTTPS 证书不存在，请先运行: {_cmd_hint('init')}")
        sys.exit(1)

    # ---- Server config ----
    host = args.host or cfg.get("server", {}).get("host", "0.0.0.0")
    port = args.port or cfg.get("server", {}).get("port", 8443)
    debug = args.debug
    no_mtls = args.no_mtls

    # Validate mTLS preconditions
    if not no_mtls:
        if not CLIENT_CERT.is_file():
            print("❌ mTLS 客户端证书不存在，请重新运行", _cmd_hint("init"))
            print("   （或传递 --no-mtls 禁用双向验证）")
            sys.exit(1)
        if not CLIENT_KEY.is_file():
            print("❌ mTLS 客户端密钥不存在，请重新运行", _cmd_hint("init"))
            sys.exit(1)

    key_type = cfg.get("ca", {}).get("key_type", "ed25519")
    validity_hours = cfg.get("ca", {}).get("validity_hours", 1)
    max_attempts = cfg.get("rate_limit", {}).get("max_attempts", 5)
    window_seconds = cfg.get("rate_limit", {}).get("window_seconds", 300)

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
        _cfg = load_config()
        body = request.get_json(silent=True)
        if not body or "totp" not in body:
            return jsonify({"success": False, "error": "缺少 totp 字段"}), 400

        totp_code = str(body["totp"]).strip()
        group_name = str(body.get("group") or "").strip()
        req_user = str(body.get("user") or "").strip()

        # 分辨率组配置（空 group_name → 自动用 default）
        gcfg = _get_group_config(_cfg, group_name)
        if gcfg is None:
            return jsonify({"success": False, "error": f"组不存在: {group_name or 'default'}"}), 400
        _users = gcfg.get("allowed_users", "")
        _secret = gcfg.get("totp_secret", "")
        _validity_hours = gcfg.get("validity_hours", validity_hours)
        _frozen = gcfg.get("frozen", False) is True or str(gcfg.get("frozen", "")).lower() in ("yes", "1", "true")

        if _frozen:
            return jsonify({"success": False, "error": f"组 {group_name or 'default'} 已被冻结"}), 403

        if not _users.strip():
            hint = f"groups users {group_name} add" if group_name else "users add"
            return jsonify({"success": False, "error": f"未配置允许用户，请运行 {hint}"}), 400

        # 用户精确匹配——指定则只签给该用户
        if req_user:
            user_list = [u.strip() for u in _users.replace(",", " ").split() if u.strip()]
            if req_user not in user_list:
                return jsonify({"success": False, "error": f"用户 {req_user} 不在允许列表中"}), 403
            _users = req_user

        if not _secret:
            hint = f"groups totp {group_name} set" if group_name else "totp"
            return jsonify({"success": False, "error": f"未配置 TOTP，请运行 {hint}"}), 400

        # Rate limit — 使用全局限速器（按 remote_addr 计数）
        client_addr = request.remote_addr or "unknown"
        if not check_rate_limit(client_addr):
            return jsonify({
                "success": False,
                "error": f"请求频繁，请等待 {window_seconds} 秒",
            }), 429

        # Verify TOTP
        group_totp = pyotp.TOTP(_secret)
        if not totp_code.isdigit() or len(totp_code) != 6:
            return jsonify({"success": False, "error": "TOTP 码格式错误"}), 400
        if not group_totp.verify(totp_code, valid_window=1):
            return jsonify({"success": False, "error": "TOTP 验证失败"}), 401

        try:
            _extensions = gcfg.get("extensions") or {}
            result = _issue_cert(key_type, _users, _validity_hours, _extensions)
        except Exception as exc:
            return jsonify({"success": False, "error": f"签发失败：{exc}"}), 500

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
        _cfg = load_config()
        _groups = _cfg.get("groups", {}) or {}
        _dg = _get_group_config(_cfg, "default")
        _d = request.args.get("level", "basic")

        _groups_info = {}
        for gname, gcfg in _groups.items():
            _resolved = _get_group_config(_cfg, gname) or gcfg
            _has_totp = bool(_resolved.get("totp_secret", ""))
            _users = _resolved.get("allowed_users", "")

            _frozen = gcfg.get("frozen") is True or str(gcfg.get("frozen", "")).lower() in ("true", "yes", "1")
            _ready = _has_totp and _users.strip() and not _frozen

            if _d == "full":
                _groups_info[gname] = {
                    "allowed_users": _users,
                    "validity_hours": _resolved.get("validity_hours", validity_hours),
                    "totp_configured": _has_totp,
                    "frozen": _frozen,
                    "parent": gcfg.get("parent", "") or None,
                    "extensions": _resolved.get("extensions", {}),
                }
            elif _ready:
                # basic: 只返回可正常使用的组
                _exts = _resolved.get("extensions", {})
                _groups_info[gname] = {
                    "allowed_users": _users,
                    "sudo": bool(_exts.get("sudo")),
                }

        result = {
            "version": VERSION,
            "ca_key_type": key_type,
            "ca_public_key": CA_KEY_PUB.read_text().strip() if CA_KEY_PUB.is_file() else None,
        }
        if _d == "full":
            result["validity_hours"] = validity_hours
            result["allowed_users"] = (_dg or {}).get("allowed_users", "")
            result["groups"] = _groups_info
        else:
            result["groups"] = _groups_info
        return jsonify(result)

    # ---- Start ----
    print(f"🚀 cert-operator v{VERSION} — CA 服务器启动中...")
    print(f"   地址: https://{host}:{port}")
    print(f"   证书有效期: {validity_hours}h")
    _dg = _get_group_config(cfg, "default")
    if _dg and _dg.get("allowed_users"):
        print(f"   允许用户: {_dg['allowed_users']}（default 组）")
    else:
        print(f"   允许用户: （空，请运行 users add）")
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


def _issue_cert(key_type: str, allowed_users: str, validity_hours: int, extensions: Optional[dict] = None) -> dict:
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

        cmd = [
            "ssh-keygen", "-s", str(CA_KEY),
            "-I", identity,
            "-n", allowed_users,
            "-V", validity,
            "-z", str(serial),
        ]
        if extensions:
            for k, v in extensions.items():
                opt = k
                val = str(v) if v else ""
                # 自动为布尔标记扩展添加 extension: 前缀
                if ":" not in opt and opt not in (
                    "clear", "force-command", "source-address", "verify-required",
                    "no-agent-forwarding", "no-port-forwarding", "no-pty",
                    "no-user-rc", "no-x11-forwarding", "permit-agent-forwarding",
                    "permit-port-forwarding", "permit-pty", "permit-user-rc",
                    "permit-x11-forwarding",
                ):
                    opt = f"extension:{opt}@cert-operator"
                if val and str(val).lower() not in ("", "true", "yes", "1"):
                    cmd += ["-O", f"{opt}={val}"]
                else:
                    cmd += ["-O", opt]
        cmd.append(str(tmp_pub))
        subprocess.run(cmd, check=True, capture_output=True, text=True)

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
# default group — migrate old global config or create on init
# ---------------------------------------------------------------------------


def _ensure_default_group(cfg: dict) -> None:
    """Create or update the ``default`` group from global config.

    On fresh install: create an empty default group.
    On upgrade (globals with data): migrate ``ca.allowed_users`` and
    ``totp_secret`` into the group, then clear the globals so future
    reads go through the group.
    """
    groups = cfg.setdefault("groups", {})
    if "default" not in groups:
        groups["default"] = {}

    dg = groups["default"]
    # Migrate allowed_users
    global_users = cfg.get("ca", {}).get("allowed_users", "")
    if global_users and not dg.get("allowed_users"):
        dg["allowed_users"] = global_users
        cfg["groups"]["default"]["allowed_users"] = ""
    # Migrate validity_hours
    global_vh = cfg.get("ca", {}).get("validity_hours", 1)
    if "validity_hours" not in dg:
        dg["validity_hours"] = global_vh
    # Migrate totp_secret from file, then purge file
    totp_secret = _read_totp_secret()
    if totp_secret and not dg.get("totp_secret"):
        dg["totp_secret"] = totp_secret
    if dg.get("totp_secret"):
        if TOTP_SECRET_FILE.is_file():
            TOTP_SECRET_FILE.unlink(missing_ok=True)
    save_config(cfg)


def _get_group_config(cfg: dict, group_name: str) -> Optional[dict]:
    """Resolve group config with parent inheritance.

    Empty *group_name* uses ``default``.  If the group has a ``parent``
    the returned dict is a **deep-merge** of ancestor configs:
    child keys override parent keys, except ``allowed_users`` which is
    **merged** (union of parent + child), and ``extensions`` which is a
    shallow dict merge (child keys win).
    """
    groups: dict = cfg.get("groups", {}) or {}
    name = group_name or "default"
    gcfg = groups.get(name)
    if gcfg is None:
        return None

    def _merge_into(child: dict, parent_name: str) -> dict:
        parent = groups.get(parent_name)
        if parent is None:
            return child
        # Recursively resolve parent's parent
        base = _merge_into(dict(parent), parent.get("parent", ""))
        result = dict(base)
        # allowed_users: union
        base_users = set(u.strip() for u in base.get("allowed_users", "").replace(",", " ").split() if u.strip())
        child_users = set(u.strip() for u in child.get("allowed_users", "").replace(",", " ").split() if u.strip())
        result["allowed_users"] = ",".join(sorted(base_users | child_users))
        # extensions: shallow merge, child wins
        merged_ext = dict(base.get("extensions") or {})
        merged_ext.update(child.get("extensions") or {})
        result["extensions"] = merged_ext
        # Other keys: child overrides base
        for k, v in child.items():
            if k == "parent":
                continue
            if k in ("allowed_users", "extensions"):
                continue  # already handled above
            if v or k in ("validity_hours",):
                result[k] = v
            elif k not in result:
                result[k] = v
        return result

    parent = gcfg.get("parent", "")
    if parent:
        merged = _merge_into(dict(gcfg), parent)
        # Keep the original group name in the result for error messages
        merged["_resolved_from"] = f"{name} → {parent}"
        return merged
    else:
        return gcfg


# ---------------------------------------------------------------------------
# renew-cert — regenerate HTTPS certificate without touching CA keys
# ---------------------------------------------------------------------------


def _cmd_renew_cert() -> None:
    """Regenerate HTTPS self-signed certificate only.  Keeps CA key pair and
    client mTLS certs intact.  Use after updating ``server.san`` in
    ``config.yaml`` to add new IPs/hostnames."""
    ensure_data_dir()
    cfg = load_config()

    if not HTTPS_KEY.is_file():
        print(f"❌ HTTPS 密钥不存在，请先运行: {_cmd_hint('init')}")
        sys.exit(1)

    san = cfg.get("server", {}).get("san", "")
    san_list = ["DNS:localhost", "IP:127.0.0.1"]
    if san.strip():
        for entry in san.replace(",", " ").split():
            entry = entry.strip()
            if entry:
                san_list.append(entry)
    san_ext = "subjectAltName=" + ",".join(san_list)

    print("🔨 重新生成 HTTPS 自签证书...")
    print(f"   SAN: {san_list}")
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
            "-addext", san_ext,
        ],
        check=True, capture_output=True,
    )
    HTTPS_KEY.chmod(0o600)
    HTTPS_CERT.chmod(0o644)
    print(f"   ✅ HTTPS 证书已更新: {HTTPS_CERT}")
    print(f"   ✅ 无需重启客户端，HTTPS 证书将自动生效")
    print()
    print(f"📋 证书 SAN（客户端必须匹配其中之一）:")
    for s in san_list:
        print(f"   {s}")
    print()
    # 重新生成 deploy.sh（内嵌 HTTPS 证书内容）
    _generate_deploy_script()


# ---------------------------------------------------------------------------
# pubkey
# ---------------------------------------------------------------------------


def _cmd_pubkey() -> None:
    if not CA_KEY_PUB.is_file():
        print(f"❌ CA 公钥不存在，请先运行: {_cmd_hint('init')}")
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
# users — manage allowed_users list
# ---------------------------------------------------------------------------


def _list_system_users() -> list[str]:
    """Return human users from /etc/passwd (UID >= 1000, not nologin)."""
    import pwd
    users = []
    for pw in pwd.getpwall():
        if pw.pw_uid >= 1000 and pw.pw_uid != 65534:
            shell = pw.pw_shell.rstrip("/")
            if not shell.endswith("nologin") and shell != "/bin/false":
                users.append(pw.pw_name)
    return sorted(users)


def _check_user_exists(username: str) -> bool:
    """Check if *username* exists as a local system user."""
    import pwd
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def _cmd_users(args) -> None:
    cfg = load_config()
    _ensure_default_group(cfg)
    dg = cfg["groups"]["default"]
    allowed_raw = dg.get("allowed_users", "")
    allowed = set()
    for name in allowed_raw.replace(",", " ").split():
        name = name.strip()
        if name:
            allowed.add(name)

    if args.action == "list":
        print("🔑 当前允许用户：")
        if allowed:
            for u in sorted(allowed):
                marker = "✅" if _check_user_exists(u) else "⚠️"
                print(f"  {marker} {u}")
        else:
            print("  （空）")
        print(f"\n总 {len(allowed)} 个")
        return

    if args.action in ("add", "set"):
        targets: list[str] = []

        if args.user is not None:
            # 从参数传入（允许传空字符串来清空）
            raw = args.user
            if raw:
                targets = [u.strip() for u in raw.replace(",", " ").split() if u.strip()]
        else:
            # 交互式选择
            system_users = _list_system_users()
            if not system_users:
                print("❌ 未找到本地系统用户（UID ≥ 1000 且有登录 shell）")
                return
            print("可选的本地系统用户：")
            for i, u in enumerate(system_users, 1):
                status = "✅" if u in allowed else "  "
                print(f"  {i:3d}. {status} {u}")
            print("\n输入编号添加（多个用逗号分隔，如 1,3,5），按回车取消：")
            try:
                raw = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not raw:
                return
            for part in raw.replace("，", ",").split(","):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(system_users):
                        targets.append(system_users[idx])
                elif part:
                    targets.append(part)

        # 校验并添加
        added = []
        skipped = []
        not_found = []
        for u in targets:
            if not _check_user_exists(u):
                not_found.append(u)
            elif u in allowed:
                skipped.append(u)
            else:
                allowed.add(u)
                added.append(u)

        if args.action == "set":
            # set 模式：覆盖全量（传空则是清空）
            allowed = set(targets)
            cfg["groups"]["default"]["allowed_users"] = ",".join(sorted(allowed))
            save_config(cfg)
            if allowed:
                print(f"✅ 已设置为: {', '.join(sorted(allowed))}")
            else:
                print("✅ 已清空允许用户列表")
            print(f"📋 当前允许用户: {cfg['groups']['default'].get('allowed_users', '') or '（空）'}")
            return

        if added:
            cfg["groups"]["default"]["allowed_users"] = ",".join(sorted(allowed))
            save_config(cfg)
            print(f"✅ 已添加: {', '.join(added)}")
        if skipped:
            print(f"⏭️  已存在: {', '.join(skipped)}")
        if not_found:
            print(f"❌ 不存在: {', '.join(not_found)}")
        return

    if args.action == "remove":
        if args.user:
            targets = [u.strip() for u in args.user.replace(",", " ").split() if u.strip()]
            removed = [u for u in targets if u in allowed]
            for u in removed:
                allowed.discard(u)
            if removed:
                cfg["groups"]["default"]["allowed_users"] = ",".join(sorted(allowed))
                save_config(cfg)
                print(f"✅ 已移除: {', '.join(removed)}")
            else:
                print("⏭️  这些用户不在允许列表中")
        else:
            if not allowed:
                print("❌ 当前允许列表为空")
                return
            print("选择要移除的用户：")
            items = sorted(allowed)
            for i, u in enumerate(items, 1):
                print(f"  {i:3d}. {u}")
            print("\n输入编号（多个用逗号分隔）：")
            try:
                raw = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not raw:
                return
            for part in raw.replace("，", ",").split(","):
                part = part.strip()
                if part.isdigit():
                    idx = int(part) - 1
                    if 0 <= idx < len(items):
                        allowed.discard(items[idx])
            cfg["groups"]["default"]["allowed_users"] = ",".join(sorted(allowed))
            save_config(cfg)
            print(f"✅ 已更新，当前允许用户: {cfg['groups']['default'].get('allowed_users', '') or '（空）'}")
        return


# ---------------------------------------------------------------------------
# groups — group-level TOTP + allowed_users
# ---------------------------------------------------------------------------


def _cmd_groups(args) -> None:
    cfg = load_config()
    groups = cfg.get("groups", {}) or {}

    if args.action == "list":
        print("📁 当前组：")
        if groups:
            for gname, gcfg in sorted(groups.items()):
                au = gcfg.get("allowed_users", "")
                vh = gcfg.get("validity_hours", cfg.get("ca", {}).get("validity_hours", 1))
                parent = gcfg.get("parent", "")
                exts = gcfg.get("extensions", {})
                print(f"  📁 {gname}{' → ' + parent if parent else ''}")
                if parent:
                    resolved = _get_group_config(cfg, gname)
                    r_au = resolved.get("allowed_users", "") if resolved else ""
                    print(f"     继承后用户: {r_au or '（空）'}")
                else:
                    print(f"     允许用户:    {au or '（未设置）'}")
                print(f"     有效期:      {vh}h")
                print(f"     TOTP:        {'✅' if gcfg.get('totp_secret') else '❌'}")
                if gcfg.get("frozen"):
                    print(f"     ❄ 已冻结")
                if exts:
                    print(f"     extensions:  {exts}")
        else:
            print("  （无）")
        return

    if args.action == "create":
        gname = args.group_name
        if not gname:
            print("❌ 请指定组名")
            return
        if gname in groups:
            print(f"❌ 组 {gname} 已存在")
            return
        groups[gname] = {
            "allowed_users": "",
            "validity_hours": 1,
            "parent": args.parent or "",
            "extensions": {},
        }
        cfg["groups"] = groups
        save_config(cfg)
        print(f"✅ 组 {gname} 已创建")
        return

    if args.action == "delete":
        gname = args.group_name
        if not gname:
            print("❌ 请指定组名")
            return
        if gname not in groups:
            print(f"❌ 组 {gname} 不存在")
            return
        del groups[gname]
        cfg["groups"] = groups
        save_config(cfg)
        print(f"✅ 组 {gname} 已删除")
        return

    if args.action in ("users", "totp", "config"):
        gname = args.group_name
        if not gname:
            print("❌ 请指定组名（groups users <组名> add <用户>）")
            return
        if gname not in groups:
            print(f"❌ 组 {gname} 不存在，请先 groups create {gname}")
            return
        gcfg = groups[gname]

        if args.action == "users":
            if args.sub_action == "list":
                au = gcfg.get("allowed_users", "")
                print(f"📁 {gname} 用户: {au or '（空）'}")
            elif args.sub_action in ("add", "remove"):
                target = args.sub_user
                if not target:
                    print("❌ 请指定用户名")
                    return
                au_set = set()
                for u in gcfg.get("allowed_users", "").replace(",", " ").split():
                    u = u.strip()
                    if u:
                        au_set.add(u)
                targets = [u.strip() for u in target.replace(",", " ").split() if u.strip()]
                if args.sub_action == "add":
                    for u in targets:
                        au_set.add(u)
                else:
                    for u in targets:
                        au_set.discard(u)
                gcfg["allowed_users"] = ",".join(sorted(au_set))
                groups[gname] = gcfg
                cfg["groups"] = groups
                save_config(cfg)
                print(f"✅ {gname} 用户已更新: {gcfg['allowed_users'] or '（空）'}")
            return

        if args.action == "totp":
            import pyotp  # noqa: F811
            if args.sub_action == "set":
                secret = pyotp.random_base32()
                gcfg["totp_secret"] = secret
                groups[gname] = gcfg
                cfg["groups"] = groups
                save_config(cfg)
                issuer = cfg.get("totp", {}).get("issuer", "CertOperator")
                account = f"{gname}-{cfg.get('totp', {}).get('account', 'admin')}"
                totp_uri = pyotp.TOTP(secret).provisioning_uri(
                    name=account, issuer_name=issuer
                )
                print(f"🔐 {gname} TOTP 已配置")
                print(f"   Secret: {secret}")
                # Print QR
                try:
                    import qrcode  # type: ignore  # noqa: F811
                    qr = qrcode.QRCode(box_size=6, border=2)
                    qr.add_data(totp_uri)
                    qr.make(fit=True)
                    qr.print_ascii()
                    img = qr.make_image(fill_color="black", back_color="white")
                    qr_path = DATA_DIR / f"totp_qrcode_{gname}.png"
                    img.save(str(qr_path))
                    print(f"   📄 图片已保存: {qr_path}")
                except ImportError:
                    print(f"   扫码 URI: {totp_uri}")
            elif args.sub_action == "verify":
                secret = gcfg.get("totp_secret")
                if not secret:
                    print(f"❌ {gname} 未配置 TOTP")
                    return
                code = pyotp.TOTP(secret).now()
                print(f"🔐 {gname} 当前验证码: {code}")
            return

        if args.action == "config":
            if args.validity_hours is not None:
                gcfg["validity_hours"] = float(args.validity_hours)
            if args.max_attempts is not None:
                gcfg.setdefault("rate_limit", {})["max_attempts"] = int(args.max_attempts)
            if args.window_seconds is not None:
                gcfg.setdefault("rate_limit", {})["window_seconds"] = int(args.window_seconds)
            if args.parent is not None:
                gcfg["parent"] = args.parent
            if args.sudo is not None:
                exts = gcfg.get("extensions") or {}
                if args.sudo.lower() in ("yes", "true", "1"):
                    exts["sudo"] = "yes"
                elif args.sudo.lower() in ("no", "false", "0", ""):
                    exts.pop("sudo", None)
                gcfg["extensions"] = exts
            if args.frozen is not None:
                if args.frozen.lower() in ("yes", "true", "1"):
                    gcfg["frozen"] = True
                elif args.frozen.lower() in ("no", "false", "0", ""):
                    gcfg["frozen"] = False
            groups[gname] = gcfg
            cfg["groups"] = groups
            save_config(cfg)
            # Print resolved config
            resolved = _get_group_config(cfg, gname)
            print(f"✅ {gname} 配置已更新")
            if resolved and resolved.get("parent"):
                src = resolved.get("_resolved_from", "")
                print(f"   📁 {gname} (上级: {resolved.get('parent')})")
                print(f"      解析后({src}): {resolved.get('allowed_users') or '（空）'}")
                if resolved.get("extensions"):
                    print(f"      extensions: {resolved['extensions']}")
            return

        return


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

    # renew-cert
    sub.add_parser("renew-cert", help="重新生成 HTTPS 证书（更新 SAN，不碰 CA 密钥）")

    # pubkey
    sub.add_parser("pubkey", help="显示 CA 公钥")

    # users
    p_users = sub.add_parser("users", help="管理允许的用户列表")
    p_users.add_argument("action", choices=["list", "add", "remove", "set"],
                         nargs="?", default="list",
                         help="操作: list 列出 | add 添加 | remove 移除 | set 覆盖设置")
    p_users.add_argument("user", nargs="?", default=None,
                         help="用户名（可逗号分隔多个，省略时进入交互模式）")

    # groups
    p_groups = sub.add_parser("groups", help="管理用户组（每组独立 TOTP + 有效期）")
    p_groups.add_argument("action", choices=["list", "create", "delete", "users", "totp", "config"],
                          nargs="?", default="list",
                          help="操作: list | create | delete | users | totp | config")
    p_groups.add_argument("group_name", nargs="?", default=None, help="组名")
    p_groups.add_argument("sub_action", nargs="?", default=None,
                          help="子操作: add | remove | list | set | verify")
    p_groups.add_argument("sub_user", nargs="?", default=None, help="用户名")
    p_groups.add_argument("--validity-hours", type=float, default=None, help="证书有效期（小时）")
    p_groups.add_argument("--max-attempts", type=int, default=None, help="限速次数")
    p_groups.add_argument("--window-seconds", type=int, default=None, help="限速窗口（秒）")
    p_groups.add_argument("--parent", type=str, default=None, help="父组名（继承其 allowed_users 和配置）")
    p_groups.add_argument("--sudo", type=str, default=None, help="证书签入 sudo 扩展（如 --sudo yes）")
    p_groups.add_argument("--frozen", type=str, default=None, help="冻结组（yes/no）")

    args = parser.parse_args()

    if args.command == "init":
        _cmd_init()
    elif args.command == "totp":
        _cmd_totp(args)
    elif args.command == "serve":
        _cmd_serve(args)
    elif args.command == "renew-cert":
        _cmd_renew_cert()
    elif args.command == "pubkey":
        _cmd_pubkey()
    elif args.command == "users":
        _cmd_users(args)
    elif args.command == "groups":
        _cmd_groups(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
