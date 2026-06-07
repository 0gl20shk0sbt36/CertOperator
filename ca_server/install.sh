#!/bin/bash
# =============================================================================
# cert-operator 服务端一键部署脚本
# 创建专用虚拟环境 + 最小权限用户运行 + 开机自启
# =============================================================================
set -euo pipefail

# ---- 颜色 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; }

# ---- 检查 root ----
if [[ $EUID -ne 0 ]]; then
    err "请以 root 身份运行此脚本"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/ca_server"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON="$VENV_DIR/bin/python"
SERVICE_NAME="cert-operator"
SERVICE_USER="cert-operator"

# =============================================================================
# 1. 创建专用用户（最小权限，无登录 shell）
# =============================================================================
if id "$SERVICE_USER" &>/dev/null; then
    info "用户 $SERVICE_USER 已存在，跳过创建"
else
    info "创建系统用户 $SERVICE_USER（无登录 shell）..."
    useradd -r -s /usr/sbin/nologin -M -d "$INSTALL_DIR" "$SERVICE_USER"
    info "用户 $SERVICE_USER 已创建"
fi

# =============================================================================
# 2. 复制文件
# =============================================================================
info "复制文件到 $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
# 清理旧生成文件
rm -rf "$INSTALL_DIR"/data "$INSTALL_DIR"/dist
# 设置所有权（后续 venv 和 init 都会由此用户执行）
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
info "文件已复制，所有权已设置"

# =============================================================================
# 3. 创建虚拟环境并安装依赖
# =============================================================================
info "创建 Python 虚拟环境..."
su -s /bin/bash "$SERVICE_USER" -c "python3 -m venv '$VENV_DIR'"
info "虚拟环境已创建: $VENV_DIR"

info "安装依赖到虚拟环境..."
su -s /bin/bash "$SERVICE_USER" -c "
    '$PYTHON' -m pip install --upgrade pip setuptools wheel -q
    '$PYTHON' -m pip install -r '$INSTALL_DIR/requirements.txt' -q
    '$PYTHON' -m pip install 'requests>=2.31' -q
"
info "依赖安装完成"

# =============================================================================
# 4. 初始化 CA
# =============================================================================
info "初始化 CA（生成密钥对、HTTPS 证书、客户端证书、部署脚本）..."
su -s /bin/bash "$SERVICE_USER" -c "cd '$INSTALL_DIR' && '$PYTHON' ca_server.py init"
info "CA 初始化完成"

# =============================================================================
# 5. 安装 systemd 服务
# =============================================================================
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

cat > "$SERVICE_FILE" << UNIT
[Unit]
Description=CertOperator CA Server — TOTP + mTLS SSH certificate authority
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$PYTHON $INSTALL_DIR/ca_server.py serve
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
info "systemd 服务已安装并启用（$SERVICE_FILE）"

# =============================================================================
# 6. 部署公钥到目标服务器的指南
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  CA 服务器部署完成！${NC}"
echo "============================================================"
echo ""
echo "下一步（手动执行）："
echo ""

echo -e "  ${YELLOW}1. 配置 TOTP${NC}"
echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py totp"
echo "     （终端会显示二维码，手机扫码绑定后运行 --verify 验证）"
echo ""

echo -e "  ${YELLOW}2. 启动服务${NC}"
echo "     sudo systemctl start $SERVICE_NAME"
echo "     sudo systemctl status $SERVICE_NAME   # 检查状态"
echo "     journalctl -u $SERVICE_NAME -f        # 查看日志"
echo ""

echo -e "  ${YELLOW}3. 查看 CA 公钥部署到目标服务器的指南${NC}"
echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py pubkey"
echo ""

echo -e "  ${YELLOW}4. 客户端部署包${NC}"
echo "     scp $INSTALL_DIR/dist/deploy.sh user@client:"
echo "     客户端运行: bash deploy.sh"
echo ""

echo -e "  ${YELLOW}5. 首次配置完成后建议设置日志轮转${NC}"
echo "     journalctl --vacuum-time=30d"
echo ""
