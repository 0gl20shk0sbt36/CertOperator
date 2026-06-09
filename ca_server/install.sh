#!/bin/bash
# =============================================================================
# cert-operator 服务端一键部署脚本
# 创建专用虚拟环境 + 最小权限用户运行 + 开机自启
# 安全覆盖：保留已有 data/  dist/  .venv
# 完全重装：bash ca-server-install.sh --clean
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

# ---- 解析参数 ----
CLEAN=0
for arg in "$@"; do
    [[ "$arg" == "--clean" ]] && CLEAN=1
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="/opt/ca_server"
VENV_DIR="$INSTALL_DIR/.venv"
PYTHON="$VENV_DIR/bin/python"
SERVICE_NAME="cert-operator"
SERVICE_USER="cert-operator"

# ---- 完全重装：先清理 ----
if [[ $CLEAN -eq 1 ]]; then
    warn "完全重装模式：将删除所有数据（证书、配置、用户）"
    # 移除旧安装数据目录，确保后续解压到空目录
    rm -rf "$INSTALL_DIR/data" "$INSTALL_DIR/dist" "$INSTALL_DIR/.venv" 2>/dev/null || true
fi

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
BACKUP_CONFIG=""
if [[ -d "$INSTALL_DIR/data" ]]; then
    BACKUP_DATA=$(mktemp -d)
    cp -r "$INSTALL_DIR/data" "$BACKUP_DATA/"
    info "已有 data/ 已备份"
fi
if [[ -f "$INSTALL_DIR/config.yaml" ]]; then
    BACKUP_CONFIG=$(mktemp)
    cp "$INSTALL_DIR/config.yaml" "$BACKUP_CONFIG"
    info "已有 config.yaml 已备份"
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

# 清理模式：调用 uninstall.sh 卸载旧安装
if [[ $CLEAN -eq 1 ]] && [[ -f "$INSTALL_DIR/uninstall.sh" ]]; then
    info "清理旧安装（保留已解压的源码）..."
    bash "$INSTALL_DIR/uninstall.sh" --yes --keep-files
    rm -f /usr/local/bin/cert-operator 2>/dev/null || true
    info "旧安装已清理"
fi

# 恢复 data/、config.yaml、dist/
if [[ -n "$BACKUP_DATA" ]]; then
    rm -rf "$INSTALL_DIR/data"
    mv "$BACKUP_DATA/data" "$INSTALL_DIR/data"
    info "data/ 已保留"
fi
if [[ -n "$BACKUP_CONFIG" ]]; then
    cp "$BACKUP_CONFIG" "$INSTALL_DIR/config.yaml"
    rm -f "$BACKUP_CONFIG"
    info "config.yaml 已保留（用户配置未丢失）"
fi
if [[ -n "$BACKUP_DIST" ]]; then
    rm -rf "$INSTALL_DIR/dist"
    mv "$BACKUP_DIST/dist" "$INSTALL_DIR/dist"
fi

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
info "文件已就绪，所有权已设置"

# ---- 停服（覆盖安装时避免文件冲突） ----
_was_running=0
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    info "停止 $SERVICE_NAME 服务..."
    systemctl stop "$SERVICE_NAME" || true
    _was_running=1
fi

# =============================================================================
# 3. 交互式配置（覆盖安装时询问保留策略，首次安装提示填写）
# =============================================================================

_is_interactive() {
    [[ -z "${NONINTERACTIVE:-}" ]] && [[ -t 0 ]]
}

CONFIG_YAML="$INSTALL_DIR/config.yaml"

if _is_interactive; then
    # 3a. 覆盖安装时确认是否保留现有配置
    OLD_SAN=""
    OLD_USERS=""
    if [[ -f "$BACKUP_CONFIG" ]]; then
        # 先读取旧值，无论用户选哪个都可能用到
        OLD_SAN=$(grep "^  san:" "$BACKUP_CONFIG" 2>/dev/null | sed 's/^  san: *"*//;s/"$//')
        OLD_USERS=$(grep "^  allowed_users:" "$BACKUP_CONFIG" 2>/dev/null | sed 's/^  allowed_users: *"*//;s/"$//')
        echo ""
        echo -e "${YELLOW}检测到已有配置（覆盖安装）${NC}"
        echo "  1) 保留现有配置（SAN、允许用户均不修改）"
        echo "  2) 重新配置（空输入保留原有字段）"
        read -r -p "请选择 [1/2] (默认 1): " cfg_choice
        if [[ "${cfg_choice:-1}" == "2" ]]; then
            BACKUP_CONFIG=""  # 丢弃备份，用新配置
            info "将使用新的配置（空输入保留原有字段）"
        else
            info "保留现有配置"
        fi
    fi

    # 3b. 配置 server.san — 自动检测 IP + 选择/手动输入
    echo ""
    echo -e "${YELLOW}服务器地址配置（用于 HTTPS 证书 SAN）${NC}"

    # 自动检测本机 IP（内网 + 公网）
    DETECTED_IPS=()
    while IFS= read -r ip; do
        ip=$(echo "$ip" | tr -d ' ')
        if [[ -n "$ip" ]] && [[ "$ip" != "127.0.0.1" ]] && [[ "$ip" != "::1" ]]; then
            DETECTED_IPS+=("$ip")
        fi
    done < <(hostname -I 2>/dev/null | tr ' ' '\n'; echo)
    # 额外尝试获取公网 IP
    if command -v curl &>/dev/null; then
        PUBLIC_IP=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || curl -s --max-time 3 ip.sb 2>/dev/null || true)
        if [[ -n "$PUBLIC_IP" ]]; then
            # 去重：如果 hostname -I 已经包含则不再重复
            found=0
            for ip in "${DETECTED_IPS[@]}"; do
                [[ "$ip" == "$PUBLIC_IP" ]] && { found=1; break; }
            done
            [[ $found -eq 0 ]] && DETECTED_IPS+=("$PUBLIC_IP")
        fi
    fi

    echo "  检测到本机 IP："
    for i in "${!DETECTED_IPS[@]}"; do
        echo "    $((i+1)). IP:${DETECTED_IPS[$i]}"
    done
    echo "  回车跳过则${OLD_SAN:+保留原有: $OLD_SAN}${OLD_SAN:-保持为空}"
    echo ""
    echo "  1) 从以上 IP 中选择（输入编号，逗号分隔多选）"
    echo "  2) 自定义输入"
    read -r -p "  请选择 [1/2] (回车跳过): " san_mode
    san_result=""
    if [[ "$san_mode" == "2" ]]; then
        read -r -p "  输入 SAN（多个用逗号分隔，如 IP:1.2.3.4,DNS:example.com）: " custom_san
        san_result="$custom_san"
    elif [[ "$san_mode" == "1" ]]; then
        read -r -p "  输入编号（逗号分隔多选，如 1,3）: " idx_input
        if [[ -n "$idx_input" ]]; then
            IFS=',' read -ra idx_parts <<< "$idx_input"
            for idx in "${idx_parts[@]}"; do
                idx=$(echo "$idx" | tr -d ' ')
                if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx >= 1 )) && (( idx <= ${#DETECTED_IPS[@]} )); then
                    san_result+="IP:${DETECTED_IPS[$((idx-1))]},"
                fi
            done
            san_result="${san_result%,}"
        fi
    elif [[ -z "$san_mode" ]] && [[ -n "$OLD_SAN" ]]; then
        san_result="$OLD_SAN"
    fi
    # 写入 config.yaml（空 + 无旧值 = 保持默认空，不写）
    if [[ -n "$san_result" ]]; then
        if grep -q "^  san:" "$CONFIG_YAML" 2>/dev/null; then
            sed -i "s/^  san:.*/  san: \"$san_result\"/" "$CONFIG_YAML"
        else
            sed -i '/^server:/a\  san: "'"$san_result"'"' "$CONFIG_YAML"
        fi
        info "SAN 已设置: $san_result"
    fi

    # 3c. 用户/组配置提示（改用 cert-operator 命令管理）
    echo ""
    echo -e "${GREEN}用户和组配置请使用 cert-operator 命令管理：${NC}"
    echo "  cert-operator users add root    # 添加全局允许用户"
    echo "  cert-operator groups create admin && cert-operator groups users admin add root"
    echo "  cert-operator groups totp admin set   # 为 admin 组配置 TOTP"
fi

# =============================================================================
# 4. 虚拟环境 + 依赖（已存在则跳过创建，更新依赖）
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
    # 如果交互式修改了 SAN，自动更新 HTTPS 证书
    if [[ -n "$san_result" ]] && [[ "$san_result" != "$OLD_SAN" ]]; then
        info "SAN 已变更，自动更新 HTTPS 证书..."
        su -s /bin/bash "$SERVICE_USER" -c "cd '$INSTALL_DIR' && '$PYTHON' ca_server.py renew-cert"
        info "HTTPS 证书已更新"
    fi
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
if [[ $_was_running -eq 1 ]]; then
    info "启动 $SERVICE_NAME 服务..."
    systemctl start "$SERVICE_NAME"
fi
info "systemd 服务已安装并启用（$SERVICE_FILE）"

# =============================================================================
# 6. 安装 cert-operator 快捷命令
# =============================================================================
cat > "/usr/local/bin/cert-operator" << 'SHORTCUT'
#!/bin/bash
sudo -u cert-operator /opt/ca_server/.venv/bin/python /opt/ca_server/ca_server.py "$@"
SHORTCUT
chmod +x /usr/local/bin/cert-operator
info "快捷命令已安装: cert-operator"

# =============================================================================
# 6b. 安装 cert-sudo-check（PAM sudo 权限检查）
# =============================================================================
if [[ -f "$INSTALL_DIR/cert-sudo-check" ]]; then
    cp "$INSTALL_DIR/cert-sudo-check" /usr/local/bin/cert-sudo-check
    chmod +x /usr/local/bin/cert-sudo-check
fi

# =============================================================================
# 7. 将 CA 公钥配置到本机 SSH（TrustedUserCAKeys）
# =============================================================================
CA_PUB="$INSTALL_DIR/data/ca_key.pub"
SSHD_CONFIG="/etc/ssh/sshd_config"
TRUST_LINE="TrustedUserCAKeys $CA_PUB"

if [[ -f "$CA_PUB" ]]; then
    # 确保 CA 公钥对其他用户可读
    chmod 644 "$CA_PUB"

    if grep -q "^TrustedUserCAKeys" "$SSHD_CONFIG" 2>/dev/null; then
        info "sshd_config 已配置 TrustedUserCAKeys，跳过"
    else
        info "配置本机 SSH 信任 CA 公钥..."
        echo "" >> "$SSHD_CONFIG"
        echo "# cert-operator CA 公钥" >> "$SSHD_CONFIG"
        echo "$TRUST_LINE" >> "$SSHD_CONFIG"
        if sshd -t 2>/dev/null; then
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true
            info "sshd 配置完成并已重启"
        else
            warn "sshd 配置语法检查失败，已回滚——请手动添加："
            warn "  $TRUST_LINE"
            # 回滚
            sed -i '/^# cert-operator CA 公钥$/d' "$SSHD_CONFIG"
            sed -i "\|^$TRUST_LINE\$|d" "$SSHD_CONFIG"
        fi
    fi
fi

# =============================================================================
# 7. 部署公钥到目标服务器的指南
# =============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  CA 服务器部署完成！${NC}"
echo "============================================================"
echo ""

if [[ ! -f "$INSTALL_DIR/data/totp_secret.txt" ]]; then
    echo "下一步（按顺序执行）："
    echo ""
    echo -e "  ${YELLOW}1. 配置管理员组（含 TOTP + sudo）${NC}"
    echo "     cert-operator groups create admin"
    echo "     cert-operator groups users admin add root"
    echo "     cert-operator groups totp admin set"
    echo "     cert-operator groups config admin --sudo yes"
    echo ""
    echo -e "  ${YELLOW}2. 启动服务${NC}"
    echo "     sudo systemctl start $SERVICE_NAME"
    echo ""
    echo -e "  ${YELLOW}3. 客户端部署包${NC}"
    echo "     scp $INSTALL_DIR/dist/deploy.sh user@client:"
    echo "     （客户端运行: bash deploy.sh）"
    echo ""
    echo -e "  ${YELLOW}4. 查看 CA 公钥（目标服务器配置用）${NC}"
    echo "     cert-operator pubkey"
    echo ""
else
    echo -e "${GREEN}  服务已在运行，覆盖安装完成。${NC}"
    echo ""
    echo -e "  ${YELLOW}管理命令：${NC}"
    echo "     sudo systemctl status $SERVICE_NAME   # 查看状态"
    echo "     sudo systemctl restart $SERVICE_NAME  # 重启服务"
    echo "     journalctl -u $SERVICE_NAME -f        # 查看日志"
    echo "     cert-operator pubkey                  # 查看 CA 公钥"
    echo "     cert-operator groups list             # 查看组配置"
fi
echo ""
