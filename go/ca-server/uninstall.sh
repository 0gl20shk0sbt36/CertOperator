#!/bin/bash
# cert-operator v2 卸载脚本
# 放在 /opt/ca_server/uninstall.sh
# 用法:
#   bash uninstall.sh                # 完全卸载
#   bash uninstall.sh --keep-data    # 保留 CA 密钥和证书
#   bash uninstall.sh --yes          # 跳过确认（供脚本调用）
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then err "请以 root 身份运行"; exit 1; fi

INSTALL_DIR="/opt/ca_server"
SERVICE_NAME="cert-operator"
SERVICE_USER="cert-operator"

FORCE=0
KEEP_DATA=0
for arg in "$@"; do
    [[ "$arg" == "--yes" ]] && FORCE=1
    [[ "$arg" == "--keep-data" ]] && KEEP_DATA=1
done

if [[ $FORCE -eq 0 ]]; then
    echo ""
    echo "============================================================"
    echo -e "${RED}  卸载 cert-operator v2${NC}"
    echo "============================================================"
    echo ""
    echo "将执行:"
    echo "  - 停止并禁用 $SERVICE_NAME 服务"
    echo "  - 删除 /etc/systemd/system/${SERVICE_NAME}.service"
    echo "  - 删除 /usr/local/bin/cert-operator"
    echo "  - 删除 /opt/ca_server/bin/ca-server"
    if [[ $KEEP_DATA -eq 0 ]]; then
        echo "  - 删除全部数据（CA 密钥、证书、配置）"
        echo "  - 删除系统用户 $SERVICE_USER"
    else
        echo "  - 保留 /opt/ca_server/data/（CA 密钥和证书）"
        echo "  - 保留系统用户 $SERVICE_USER"
    fi
    echo ""
    read -r -p "确认卸载？(y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "已取消"; exit 0
    fi
fi

# 1. 停止并禁用服务
if systemctl list-unit-files --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    info "停止并禁用服务..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload 2>/dev/null || true
    info "服务已清理"
fi

# 2. 删除快捷命令
rm -f /usr/local/bin/cert-operator
info "快捷命令已删除"

# 3. 删除安装目录（保留数据时只删 bin/、config.json、dist/）
if [[ -d "$INSTALL_DIR" ]]; then
    if [[ $KEEP_DATA -eq 1 ]]; then
    rm -rf "$INSTALL_DIR/bin" "$INSTALL_DIR/dist" 2>/dev/null || true
    rm -f "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
        info "安装目录已清理（保留 data/）"
    else
        rm -rf "$INSTALL_DIR"
        info "安装目录已删除"
    fi
fi

# 4. 删除专用用户（保留数据时不删用户，否则 data/ 的文件会变成孤儿）
if [[ $KEEP_DATA -eq 0 ]] && id "$SERVICE_USER" &>/dev/null; then
    info "删除系统用户 $SERVICE_USER ..."
    userdel -r "$SERVICE_USER" 2>/dev/null || userdel "$SERVICE_USER" 2>/dev/null || true
    info "用户已删除"
fi

echo ""
echo -e "${GREEN}✅ 卸载完成${NC}"