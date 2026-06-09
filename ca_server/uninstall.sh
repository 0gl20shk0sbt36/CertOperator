#!/bin/bash
# =============================================================================
# cert-operator 服务端卸载脚本
# 停止服务 → 删除文件 → 删除用户 → 清理 systemd
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

if [[ $EUID -ne 0 ]]; then
    err "请以 root 身份运行此脚本"
    exit 1
fi

INSTALL_DIR="/opt/ca_server"
SERVICE_NAME="cert-operator"
SERVICE_USER="cert-operator"

# --yes 参数跳过确认（供 install.sh --clean 调用）
FORCE=0
KEEP_FILES=0
for arg in "$@"; do
    [[ "$arg" == "--yes" ]] && FORCE=1
    [[ "$arg" == "--keep-files" ]] && KEEP_FILES=1
done

if [[ $FORCE -eq 0 ]]; then
    echo ""
    echo "============================================================"
    echo -e "${RED}  卸载 cert-operator CA 服务器${NC}"
    echo "============================================================"
    echo ""
    echo "将执行以下操作："
    echo "  - 停止并禁用 $SERVICE_NAME 服务"
    echo "  - 删除 /etc/systemd/system/${SERVICE_NAME}.service"
    echo "  - 删除 $INSTALL_DIR"
    echo "  - 删除系统用户 $SERVICE_USER"
    echo ""
    read -r -p "确认卸载？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "已取消"
        exit 0
    fi
fi

# ---- 1. 停止并禁用服务 ----
if systemctl list-unit-files --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    info "停止并禁用服务..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    info "服务已清理"
fi

# ---- 2. 删除安装目录 ----
if [[ $KEEP_FILES -eq 0 ]] && [[ -d "$INSTALL_DIR" ]]; then
    info "删除 $INSTALL_DIR ..."
    rm -rf "$INSTALL_DIR"
    info "安装目录已删除"
fi

# ---- 3. 删除专用用户 ----
if id "$SERVICE_USER" &>/dev/null; then
    info "删除系统用户 $SERVICE_USER ..."
    userdel -r "$SERVICE_USER" 2>/dev/null || userdel "$SERVICE_USER" 2>/dev/null || true
    info "用户已删除"
fi

echo ""
echo -e "${GREEN}✅ 卸载完成${NC}"
echo ""
