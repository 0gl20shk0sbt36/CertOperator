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
BIN="$INSTALL_DIR/bin/ca-server"
SERVICE_USER="cert-operator"
SERVICE_NAME="cert-operator"

# 检查二进制
if [[ ! -f "$BIN" ]]; then
    err "请先将 ca-server 二进制放到 $BIN"
    exit 1
fi

info "创建用户 $SERVICE_USER ..."
id "$SERVICE_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin -M "$SERVICE_USER"

mkdir -p "$INSTALL_DIR/bin"
cp "$BIN" "$INSTALL_DIR/bin/ca-server"
chmod 750 "$INSTALL_DIR/bin/ca-server"
chown "root:$SERVICE_USER" "$INSTALL_DIR/bin/ca-server"
chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# 安装快捷命令（通过 sudo -u cert-operator 确保以专用用户运行）
cat > /usr/local/bin/cert-operator << 'SHORTCUT'
#!/bin/bash
exec sudo -u cert-operator /opt/ca_server/bin/ca-server "$@"
SHORTCUT
chmod 755 /usr/local/bin/cert-operator
info "快捷命令: cert-operator → sudo -u cert-operator /opt/ca_server/bin/ca-server"

# 初始化 CA
info "初始化 CA..."
su -s /bin/bash "$SERVICE_USER" -c "cd '$INSTALL_DIR' && '$INSTALL_DIR/bin/ca-server' init"

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

echo ""
echo "✅ 部署完成"
echo "   启动: systemctl start $SERVICE_NAME"
echo "   版本: $($INSTALL_DIR/bin/ca-server version)"
