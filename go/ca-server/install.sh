#!/bin/bash
# cert-operator v2 一键部署（Go version）
# 用法: bash install.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then err "请以 root 身份运行"; exit 1; fi

INSTALL_DIR="/opt/ca_server"
BIN="${CA_SERVER_BIN:-$(dirname "$0")/ca-server}"
BIN_DEST="$INSTALL_DIR/bin/ca-server"
SERVICE_USER="cert-operator"
SERVICE_NAME="cert-operator"

# 检查二进制
SOURCE_BIN="${CA_SERVER_BIN:-$(dirname "$0")/ca-server}"
if [[ ! -f "$SOURCE_BIN" ]]; then
    err "未找到 ca-server 二进制"
    err "请将 ca-server 放在 install.sh 同目录，或通过 CA_SERVER_BIN 环境变量指定"
    err "  cp /path/to/ca-server $(dirname "$0")/"
    err "  # 或"
    err "  CA_SERVER_BIN=/path/to/ca-server bash install.sh"
    exit 1
fi

info "创建用户 $SERVICE_USER ..."
id "$SERVICE_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin -M "$SERVICE_USER"

mkdir -p "$INSTALL_DIR/bin"
cp "$SOURCE_BIN" "$BIN_DEST"
chmod 750 "$BIN_DEST"
chown "root:$SERVICE_USER" "$BIN_DEST"
chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# 安装快捷命令（通过 sudo -u cert-operator 确保以专用用户运行）
cat > /usr/local/bin/cert-operator << 'SHORTCUT'
#!/bin/bash
cd /opt/ca_server
exec sudo -u cert-operator /opt/ca_server/bin/ca-server "$@"
SHORTCUT
chmod 755 /usr/local/bin/cert-operator
info "快捷命令: cert-operator → sudo -u cert-operator /opt/ca_server/bin/ca-server"

# 创建默认配置
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    cat > "$INSTALL_DIR/config.json" << CFG
{
  "ca": { "key_type": "ed25519", "validity_minutes": 60 },
  "server": { "host": "0.0.0.0", "port": 8443 },
  "rate_limit": { "max_attempts": 5, "window_seconds": 300 },
  "totp": { "issuer": "CertOperator", "account": "admin" }
}
CFG
    chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/config.json"
    info "默认配置已创建: $INSTALL_DIR/config.json"
fi

# 初始化 CA
info "初始化 CA..."
su -s /bin/bash "$SERVICE_USER" -c "cd '$INSTALL_DIR' && '$BIN_DEST' init"

# 拷贝卸载脚本到安装目录
if [[ -f "$(dirname "$0")/uninstall.sh" ]]; then
    cp "$(dirname "$0")/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
    chmod 755 "$INSTALL_DIR/uninstall.sh"
    chown "root:$SERVICE_USER" "$INSTALL_DIR/uninstall.sh"
    info "卸载脚本: $INSTALL_DIR/uninstall.sh"
fi

# systemd 服务
cat > /etc/systemd/system/$SERVICE_NAME.service << UNIT
[Unit]
Description=cert-operator v2 — TOTP + mTLS SSH CA
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/ca-server serve
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable "$SERVICE_NAME" 2>/dev/null || true
info "systemd 服务已安装 ($SERVICE_NAME)"

# 安装 cert-sudo-check + 配置 PAM
SRC_CSC="$(dirname "$0")/cert-sudo-check"
if [[ -f "$SRC_CSC" ]]; then
    cp "$SRC_CSC" /usr/local/bin/cert-sudo-check
    chmod +x /usr/local/bin/cert-sudo-check
    PAM_FILE="/etc/pam.d/sudo"
    if [[ -f "$PAM_FILE" ]] && ! grep -q "cert-sudo-check" "$PAM_FILE" 2>/dev/null; then
        cp "$PAM_FILE" "${PAM_FILE}.bak.cert-operator.$(date +%s)"
        HEADER=$(head -1 "$PAM_FILE")
        {
            echo "$HEADER"
            echo "# cert-operator: SSH 证书扩展检查"
            echo "auth sufficient pam_exec.so quiet /usr/local/bin/cert-sudo-check"
            echo "auth sufficient pam_unix.so"
            echo "auth requisite  pam_deny.so"
            tail -n +2 "$PAM_FILE"
        } > "${PAM_FILE}.new"
        mv "${PAM_FILE}.new" "$PAM_FILE"
        info "PAM sudo 已配置"
    fi
fi

echo ""
echo "✅ 部署完成"
echo "   启动: systemctl start $SERVICE_NAME"
echo "   版本: $($BIN_DEST version)"
