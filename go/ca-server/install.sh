#!/bin/bash
# cert-operator v2 一键部署（Go version）
# 用法: bash install.sh [--clean]
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
err()   { echo -e "${RED}[ERR]${NC} $*" >&2; }

[[ $EUID -ne 0 ]] && { err "请以 root 身份运行"; exit 1; }

INSTALL_DIR="/opt/ca_server"
BIN_DEST="$INSTALL_DIR/bin/ca-server"
SERVICE_USER="cert-operator"
SERVICE_NAME="cert-operator"

CLEAN=0
for arg in "$@"; do
    case "$arg" in --clean) CLEAN=1 ;; esac
done

# 如果存在旧安装，先清理再重装（兼容旧版 uninstall 无 --yes 的情况）
if [[ -d "$INSTALL_DIR" ]]; then
    if [[ "$CLEAN" -eq 1 ]]; then
        info "检测到旧安装，执行完全清理..."
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -rf "$INSTALL_DIR" /etc/systemd/system/${SERVICE_NAME}.service
        rm -f /usr/local/bin/cert-operator
        systemctl daemon-reload 2>/dev/null || true
        userdel -r "$SERVICE_USER" 2>/dev/null || userdel "$SERVICE_USER" 2>/dev/null || true
    else
        info "检测到旧安装，执行保留数据清理..."
        # 尽量调用旧卸载脚本（可能不支持 --yes，失败则手动清理）
        if grep -q -- "--yes" "$INSTALL_DIR/uninstall.sh" 2>/dev/null; then
            bash "$INSTALL_DIR/uninstall.sh" --yes --keep-data
        else
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            systemctl disable "$SERVICE_NAME" 2>/dev/null || true
            rm -f /usr/local/bin/cert-operator
            rm -rf "$INSTALL_DIR/bin" "$INSTALL_DIR/dist"
            rm -f "$INSTALL_DIR/uninstall.sh" /etc/systemd/system/${SERVICE_NAME}.service
            systemctl daemon-reload 2>/dev/null || true
            # 不删 data/、不删用户
        fi
    fi
fi

mkdir -p "$INSTALL_DIR/bin"

# 检查二进制
SOURCE_BIN="${CA_SERVER_BIN:-$(dirname "$0")/ca-server}"
if [[ ! -f "$SOURCE_BIN" ]]; then
    err "未找到 ca-server 二进制"
    err "请将 ca-server 放在 install.sh 同目录，或通过 CA_SERVER_BIN 环境变量指定"
    exit 1
fi

cp "$SOURCE_BIN" "$BIN_DEST"
chmod 750 "$BIN_DEST"
chown "root:$SERVICE_USER" "$BIN_DEST"

# 创建用户
info "创建用户 $SERVICE_USER ..."
id "$SERVICE_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin -M "$SERVICE_USER"
chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# 安装快捷命令
cat > /usr/local/bin/cert-operator << 'SHORTCUT'
#!/bin/bash
cd /opt/ca_server
exec sudo -u cert-operator /opt/ca_server/bin/ca-server "$@"
SHORTCUT
chmod 755 /usr/local/bin/cert-operator
info "快捷命令: cert-operator → sudo -u cert-operator /opt/ca_server/bin/ca-server"

# 创建默认配置
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    LOCAL_IPS=""
    if command -v ip &>/dev/null; then
        LOCAL_IPS=$(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' | grep -v '127.0.0.1' | tr '\n' ',' | sed 's/,$//')
    fi
    if [[ -z "$LOCAL_IPS" ]] && command -v hostname &>/dev/null; then
        LOCAL_IPS=$(hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//')
    fi
    SAN="DNS:localhost,IP:127.0.0.1"
    if [[ -n "$LOCAL_IPS" ]]; then
        IFS=',' read -ra IPS <<< "$LOCAL_IPS"
        for ip in "${IPS[@]}"; do
            ip=$(echo "$ip" | xargs)
            [[ -n "$ip" ]] && SAN="$SAN,IP:$ip"
        done
        info "检测到本地 IP: $LOCAL_IPS"
    fi
    PUBLIC_IP=$(curl -s --connect-timeout 3 https://api.ipify.org 2>/dev/null || \
                curl -s --connect-timeout 3 https://ifconfig.me 2>/dev/null || true)
    if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" != *"timed out"* ]]; then
        SAN="$SAN,IP:$PUBLIC_IP"
        info "检测到公网 IP: $PUBLIC_IP"
    fi
    info "HTTPS 证书 SAN: $SAN"
    cat > "$INSTALL_DIR/config.json" << CFG
{
  "ca": { "key_type": "ed25519", "validity_minutes": 60 },
  "server": { "host": "0.0.0.0", "port": 8443, "san": "$SAN" },
  "rate_limit": { "max_attempts": 5, "window_seconds": 300 },
  "totp": { "issuer": "CertOperator", "account": "admin" }
}
CFG
    chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/config.json"
    info "默认配置已创建: $INSTALL_DIR/config.json"
fi

# 检查 CA 是否已初始化，未初始化则提示
if [[ -f "$INSTALL_DIR/data/ca_key" ]]; then
    info "CA 密钥已存在（data/ 保留完好）"
else
    info "CA 未初始化，请手动执行: cert-operator init"
fi

# 拷贝卸载脚本
SRC_UNINSTALL="$(dirname "$0")/uninstall.sh"
if [[ -f "$SRC_UNINSTALL" ]]; then
    cp "$SRC_UNINSTALL" "$INSTALL_DIR/uninstall.sh"
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

# 部署 sudo-wrapper（dpkg-divert + cert-sudo-check + PAM）
SRC_SC="$(dirname "$0")/cert-sudo-check"
SRC_SW="$(dirname "$0")/sudo-wrapper"

if [[ -f "$SRC_SC" ]]; then
    cp -f "$SRC_SC" /usr/local/bin/cert-sudo-check
    chmod +x /usr/local/bin/cert-sudo-check
    info "cert-sudo-check 已更新 → /usr/local/bin/cert-sudo-check"
else
    warn "cert-sudo-check 未找到，跳过更新（文件缺失: $SRC_SC）"
fi

if [[ -f "$SRC_SW" ]]; then
    if [[ ! -f /usr/bin/_sudo ]]; then
        dpkg-divert --divert /usr/bin/_sudo --rename /usr/bin/sudo
    fi
    cp -f "$SRC_SW" /usr/bin/sudo
    chmod 755 /usr/bin/sudo
    info "sudo-wrapper 已部署 → /usr/bin/sudo"
else
    warn "sudo-wrapper 未找到，跳过部署（文件缺失: $SRC_SW）"
fi

# PAM 配置
PAM_FILE="/etc/pam.d/sudo"
if [[ -f "$PAM_FILE" ]] && ! grep -q "cert-sudo-check" "$PAM_FILE" 2>/dev/null; then
    cp "$PAM_FILE" "${PAM_FILE}.bak.cert-operator.$(date +%s)"
    HEADER=$(head -1 "$PAM_FILE")
    {
        echo "$HEADER"
        echo "# cert-operator"
        echo "auth sufficient pam_exec.so /usr/local/bin/cert-sudo-check"
        echo "auth sufficient pam_unix.so"
        echo "auth requisite  pam_deny.so"
        tail -n +2 "$PAM_FILE"
    } > "${PAM_FILE}.new"
    mv "${PAM_FILE}.new" "$PAM_FILE"
    info "PAM sudo 已配置"
fi

# 确保数据目录可读（修复旧版本 0700 目录）
if [[ -d "$INSTALL_DIR/data" ]]; then
    chmod 755 "$INSTALL_DIR/data" 2>/dev/null || true
fi

# 重启服务（之前被卸载脚本停止的）
if systemctl list-unit-files --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    systemctl start "$SERVICE_NAME"
    info "服务已重新启动"
fi

echo ""
echo "✅ 部署完成"
echo "   首次使用前需初始化: cert-operator init"
echo "   启动/重启: systemctl start $SERVICE_NAME"