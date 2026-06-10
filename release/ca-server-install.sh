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

# ---- 检查依赖 ----
MISSING_DEPS=()
for dep in python3 openssl curl; do
    command -v "$dep" &>/dev/null || MISSING_DEPS+=("$dep")
done
if [[ ${#MISSING_DEPS[@]} -gt 0 ]]; then
    err "缺少以下依赖：${MISSING_DEPS[*]}"
    echo ""
    echo "请先安装："
    echo "  apt install -y python3 python3-pip python3-venv openssl curl"
    echo "  （或对应发行版的包管理器命令）"
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

# =============================================================================
# 回滚机制
# =============================================================================
ROLLBACK_DIR=$(mktemp -d)
ROLLBACK_NEEDED=0

_rollback() {
    local rc=$?
    if [[ $ROLLBACK_NEEDED -eq 0 ]]; then
        rm -rf "$ROLLBACK_DIR" 2>/dev/null || true
        exit $rc
    fi
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}[ROLLBACK] 安装过程发生错误 (exit code $rc)，正在回滚...${NC}"
    echo -e "${RED}========================================${NC}"

    # 1. 恢复 PAM sudo 配置（最关键：配坏了所有用户 sudo 都会坏）
    if [[ -f "$ROLLBACK_DIR/pam_sudo.backup" ]]; then
        cp "$ROLLBACK_DIR/pam_sudo.backup" /etc/pam.d/sudo 2>/dev/null || true
        info "PAM sudo 配置已恢复"
    fi

    # 2. 恢复 sshd_config
    if [[ -f "$ROLLBACK_DIR/sshd_config.backup" ]]; then
        cp "$ROLLBACK_DIR/sshd_config.backup" /etc/ssh/sshd_config 2>/dev/null || true
        info "sshd_config 已恢复"
        if command -v sshd &>/dev/null; then
            sshd -t 2>/dev/null && (systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || true)
        fi
    fi

    # 3. 移除新增的 systemd 服务（安装前不存在的才移除）
    if [[ -f "$ROLLBACK_DIR/systemd_service.new" ]]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        info "systemd 服务已清理"
    fi

    # 4. 移除新安装的快捷命令
    if [[ -f "$ROLLBACK_DIR/cert_operator.new" ]]; then
        rm -f /usr/local/bin/cert-operator 2>/dev/null || true
    fi

    # 5. 移除新安装的 cert-sudo-check
    if [[ -f "$ROLLBACK_DIR/cert_sudo_check.new" ]]; then
        rm -f /usr/local/bin/cert-sudo-check 2>/dev/null || true
    fi

    # 6. 恢复 INSTALL_DIR 数据备份
    if [[ -n "${BACKUP_DATA:-}" ]] && [[ -d "$BACKUP_DATA/data" ]]; then
        rm -rf "$INSTALL_DIR/data" 2>/dev/null || true
        cp -r "$BACKUP_DATA/data" "$INSTALL_DIR/data" 2>/dev/null || true
        chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/data" 2>/dev/null || true
        info "CA 数据已恢复"
    fi
    if [[ -n "${BACKUP_CONFIG:-}" ]] && [[ -f "$BACKUP_CONFIG" ]]; then
        cp "$BACKUP_CONFIG" "$INSTALL_DIR/config.yaml" 2>/dev/null || true
        info "配置已恢复"
    fi
    if [[ -n "${BACKUP_DIST:-}" ]] && [[ -d "$BACKUP_DIST/dist" ]]; then
        rm -rf "$INSTALL_DIR/dist" 2>/dev/null || true
        cp -r "$BACKUP_DIST/dist" "$INSTALL_DIR" 2>/dev/null || true
    fi

    # 7. 清理新建的虚拟环境
    if [[ -f "$ROLLBACK_DIR/venv.new" ]] && [[ -d "$VENV_DIR" ]]; then
        rm -rf "$VENV_DIR" 2>/dev/null || true
    fi

    rm -rf "$ROLLBACK_DIR" 2>/dev/null || true
    echo -e "${RED}[ROLLBACK] 回滚完成，安装已中止 (exit code $rc)${NC}"
    exit $rc
}
trap '_rollback' ERR

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
    BACKUP_CONFIG=""  # 标记已处理，回滚时不再重复恢复
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

# ---- 记录修改前的系统状态，用于回滚 ----
# PAM
cp /etc/pam.d/sudo "$ROLLBACK_DIR/pam_sudo.backup" 2>/dev/null || true
# sshd_config
cp /etc/ssh/sshd_config "$ROLLBACK_DIR/sshd_config.backup" 2>/dev/null || true
# systemd 服务状态
if [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
    touch "$ROLLBACK_DIR/systemd_service.existed"
else
    touch "$ROLLBACK_DIR/systemd_service.new"
fi
# 快捷命令状态
if [[ -f /usr/local/bin/cert-operator ]]; then
    touch "$ROLLBACK_DIR/cert_operator.existed"
else
    touch "$ROLLBACK_DIR/cert_operator.new"
fi
# cert-sudo-check 状态
if [[ -f /usr/local/bin/cert-sudo-check ]]; then
    touch "$ROLLBACK_DIR/cert_sudo_check.existed"
else
    touch "$ROLLBACK_DIR/cert_sudo_check.new"
fi
# 虚拟环境状态
if [[ -d "$VENV_DIR" ]]; then
    touch "$ROLLBACK_DIR/venv.existed"
else
    touch "$ROLLBACK_DIR/venv.new"
fi

ROLLBACK_NEEDED=1
info "回滚快照已记录"

# =============================================================================
# 3. 交互式配置（覆盖安装时询问保留策略，首次安装提示填写）
# =============================================================================

_is_interactive() {
    [[ -z "${NONINTERACTIVE:-}" ]] && [[ -t 0 ]]
}

CONFIG_YAML="$INSTALL_DIR/config.yaml"
san_result=""
OLD_SAN=""
OLD_USERS=""

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

systemctl daemon-reload 2>/dev/null || true
systemctl enable "$SERVICE_NAME" 2>/dev/null || true
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
# 6b. 安装 cert-sudo-check + 配置 PAM
# =============================================================================
if [[ -f "$INSTALL_DIR/cert-sudo-check" ]]; then
    cp "$INSTALL_DIR/cert-sudo-check" /usr/local/bin/cert-sudo-check
    chmod +x /usr/local/bin/cert-sudo-check
    # 配置 PAM（遇到已配置则跳过，保证幂等）
    PAM_FILE="/etc/pam.d/sudo"
    if [[ -f "$PAM_FILE" ]]; then
        if grep -q "cert-sudo-check" "$PAM_FILE" 2>/dev/null; then
            if grep -q "quiet.*cert-sudo-check" "$PAM_FILE" 2>/dev/null; then
                :  # 已有 cert-operator 配置且已优化，跳过
            else
                # 旧版 cert-operator PAM（无 quiet）→ 升级
                info "PAM sudo 配置已升级（quiet 模式）"
                sed -i "s|auth sufficient pam_exec.so /usr/local/bin/cert-sudo-check|auth sufficient pam_exec.so quiet /usr/local/bin/cert-sudo-check|" "$PAM_FILE"
            fi
        else
            # 备份原始文件
            cp "$PAM_FILE" "${PAM_FILE}.bak.cert-operator.$(date +%s)"
            # 构建新配置：保留 #%PAM-1.0 在第一行，插入 cert-operator 规则
            # 注意：PAM 魔数 #%PAM-1.0 必须是文件第一行
            HEADER=$(head -1 "$PAM_FILE")
            {
                echo "$HEADER"
                echo "# cert-operator: SSH 证书扩展检查（证书含 sudo 扩展免密码，否则降级到密码）"
                echo "auth sufficient pam_exec.so quiet /usr/local/bin/cert-sudo-check"
                echo "auth sufficient pam_unix.so"
                echo "auth requisite  pam_deny.so"
                tail -n +2 "$PAM_FILE"
            } > "${PAM_FILE}.new"
            mv "${PAM_FILE}.new" "$PAM_FILE"
            info "PAM sudo 已配置"
        fi
    fi
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
    echo "     cert-operator groups config admin set sudo yes"
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

# ---- 成功：清理回滚数据 ----
rm -rf "$ROLLBACK_DIR" 2>/dev/null || true
ROLLBACK_NEEDED=0
exit 0

exit 0
#__CERT_OP_ARCHIVE__
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
L/0/g+RNYABoAQA=
