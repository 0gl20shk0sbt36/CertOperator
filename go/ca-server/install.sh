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
BIN="/usr/local/bin/ca-server"
SERVICE_USER="cert-operator"
SERVICE_NAME="cert-operator"

# 依赖检查
for dep in ca-server ssh-keygen; do
    command -v "$dep" &>/dev/null || MISSING_DEPS+=("$dep")
done
if [[ -f "$BIN" ]]; then :; else MISSING_DEPS+=("ca-server (不在 /usr/local/bin)"); fi
if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    err "缺少依赖: ${MISSING_DEPS[*]}"; exit 1
fi

info "创建用户 $SERVICE_USER ..."
id "$SERVICE_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin -M "$SERVICE_USER"

mkdir -p "$INSTALL_DIR"
chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# 初始化 CA
info "初始化 CA..."
su -s /bin/bash "$SERVICE_USER" -c "cd '$INSTALL_DIR' && $BIN init"

# 配置快捷命令
ln -sf "$BIN" /usr/local/bin/cert-operator 2>/dev/null || true
info "快捷命令: cert-operator"

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
ExecStart=$BIN serve
Restart=on-failure
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
info "systemd 服务已安装"

echo ""
echo "✅ 部署完成"
echo "   启动: systemctl start $SERVICE_NAME"
echo "   版本: $($BIN version)"
