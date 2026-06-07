#!/bin/bash
# =============================================================================
# cert-operator 服务端一键部署脚本
# 创建专用虚拟环境 + 最小权限用户运行 + 开机自启
# 安全覆盖：保留已有 data/  dist/  .venv
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
# 2. 解压文件，保留已有 data/ dist/ .venv
# =============================================================================
BACKUP_DATA=""
if [[ -d "$INSTALL_DIR/data" ]]; then
    BACKUP_DATA=$(mktemp -d)
    cp -r "$INSTALL_DIR/data" "$BACKUP_DATA/"
    info "已有 data/ 已备份"
fi
BACKUP_DIST=""
if [[ -d "$INSTALL_DIR/dist" ]]; then
    BACKUP_DIST=$(mktemp -d)
    cp -r "$INSTALL_DIR/dist" "$BACKUP_DIST/"
fi

if grep -q "^#__CERT_OP_ARCHIVE__$" "$0" 2>/dev/null; then
    info "自解压模式..."
    mkdir -p "$INSTALL_DIR"
    ARCHIVE_LINE=$(grep -n "^#__CERT_OP_ARCHIVE__$" "$0" | head -1 | cut -d: -f1)
    tail -n +$((ARCHIVE_LINE + 1)) "$0" | base64 -d | tar -xzf - \
        --strip-components=1 -C "$INSTALL_DIR"
    info "自解压完成"
elif TARBALL=$(ls "$SCRIPT_DIR"/ca-server*.tar.gz 2>/dev/null | head -1) && [[ -n "$TARBALL" ]]; then
    info "从压缩包解压: $(basename "$TARBALL") ..."
    mkdir -p "$INSTALL_DIR"
    tar -xzf "$TARBALL" --strip-components=1 -C "$INSTALL_DIR"
    info "解压完成"
else
    info "从源码目录复制..."
    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    rm -rf "$INSTALL_DIR"/__pycache__ "$INSTALL_DIR"/.venv
fi

# 恢复 data/ 和 dist/
if [[ -n "$BACKUP_DATA" ]]; then
    rm -rf "$INSTALL_DIR/data"
    mv "$BACKUP_DATA/data" "$INSTALL_DIR/data"
    info "data/ 已保留"
fi
if [[ -n "$BACKUP_DIST" ]]; then
    rm -rf "$INSTALL_DIR/dist"
    mv "$BACKUP_DIST/dist" "$INSTALL_DIR/dist"
fi

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
info "文件已就绪，所有权已设置"

# =============================================================================
# 3. 虚拟环境 + 依赖（已存在则跳过创建，更新依赖）
# =============================================================================
if [[ -f "$VENV_DIR/bin/python" ]]; then
    info "虚拟环境已存在，跳过创建"
else
    info "创建 Python 虚拟环境..."
    su -s /bin/bash "$SERVICE_USER" -c "python3 -m venv '$VENV_DIR'"
    info "虚拟环境已创建"
fi

info "更新依赖..."
# 镜像源加速：pip 会自动读取 PIP_INDEX_URL 环境变量
# 国内服务器建议先 export PIP_INDEX_URL=https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple
su -s /bin/bash "$SERVICE_USER" -c "
    export PIP_INDEX_URL='${PIP_INDEX_URL:-}'
    '$PYTHON' -m pip install --upgrade pip setuptools wheel -q --default-timeout=60 --retries=3
    '$PYTHON' -m pip install -r '$INSTALL_DIR/requirements.txt' -q --default-timeout=60 --retries=3
    '$PYTHON' -m pip install 'requests>=2.31' -q --default-timeout=60 --retries=3
"
info "依赖更新完成"

# =============================================================================
# 4. 初始化 CA（已有密钥则跳过）
# =============================================================================
if [[ -f "$INSTALL_DIR/data/ca_key" ]]; then
    info "CA 密钥已存在，跳过初始化"
else
    info "初始化 CA（生成密钥对、HTTPS 证书、客户端证书、部署脚本）..."
    su -s /bin/bash "$SERVICE_USER" -c "cd '$INSTALL_DIR' && '$PYTHON' ca_server.py init"
    info "CA 初始化完成"
fi

# =============================================================================
# 5. 安装 / 更新 systemd 服务
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
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "正在重启服务以应用更新..."
    systemctl restart "$SERVICE_NAME"
fi
info "systemd 服务已安装并启用（$SERVICE_FILE）"

# =============================================================================
# 6. 部署公钥到目标服务器的指南
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  CA 服务器部署完成！${NC}"
echo "============================================================"
echo ""

if [[ ! -f "$INSTALL_DIR/data/totp_secret.txt" ]]; then
    echo "下一步（按顺序执行）："
    echo ""
    echo -e "  ${YELLOW}1. 添加允许 SSH 登录的用户${NC}"
    echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py users add root"
    echo ""
    echo -e "  ${YELLOW}2. 配置 TOTP${NC}"
    echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py totp"
    echo "     （终端会显示二维码，手机扫码绑定后运行 --verify 验证）"
    echo ""
    echo -e "  ${YELLOW}3. 启动服务${NC}"
    echo "     sudo systemctl start $SERVICE_NAME"
    echo ""
    echo -e "  ${YELLOW}4. 客户端部署包${NC}"
    echo "     scp $INSTALL_DIR/dist/deploy.sh user@client:"
    echo "     （客户端运行: bash deploy.sh）"
    echo ""
    echo -e "  ${YELLOW}5. 查看 CA 公钥（目标服务器配置用）${NC}"
    echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py pubkey"
    echo ""
else
    echo -e "${GREEN}  服务已在运行，覆盖安装完成。${NC}"
    echo ""
    echo -e "  ${YELLOW}管理命令：${NC}"
    echo "     sudo systemctl status $SERVICE_NAME   # 查看状态"
    echo "     sudo systemctl restart $SERVICE_NAME  # 重启服务"
    echo "     journalctl -u $SERVICE_NAME -f        # 查看日志"
    echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py pubkey"
    echo "     sudo -u $SERVICE_USER $PYTHON $INSTALL_DIR/ca_server.py totp --verify"
fi
echo ""
