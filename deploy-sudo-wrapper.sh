#!/bin/bash
# =============================================================================
# deploy-sudo-wrapper.sh — 在目标服务器上部署/卸载 cert-operator sudo wrapper
#
#  用法:
#     sudo bash deploy-sudo-wrapper.sh              # 部署
#     sudo bash deploy-sudo-wrapper.sh --uninstall  # 卸载
#     sudo bash deploy-sudo-wrapper.sh [CA_PATH]    # 部署，指定 CA 公钥路径
# =============================================================================
set -euo pipefail

if [[ "${1:-}" == "--uninstall" ]]; then
    echo "=== 卸载 cert-operator sudo wrapper ==="
    # 1. 从 dpkg-divert 恢复原 sudo
    if [[ -f /usr/bin/_sudo ]]; then
        rm -f /usr/bin/sudo 2>/dev/null
        dpkg-divert --rename --remove /usr/bin/sudo 2>/dev/null || true
        echo "  dpkg-divert 已移除，sudo 已恢复"
    fi
    # 2. 如果 diversion 未恢复但 _sudo 还在，手动恢复
    if [[ ! -f /usr/bin/sudo && -f /usr/bin/_sudo ]]; then
        mv /usr/bin/_sudo /usr/bin/sudo
        echo "  _sudo 已移回 /usr/bin/sudo"
    fi
    # 3. 如果两边都没有
    if [[ ! -f /usr/bin/sudo ]]; then
        echo "  错误: sudo 未找到，请运行 apt reinstall sudo" >&2
    fi
    # 删 cert-sudo-check
    if [[ -f /usr/local/bin/cert-sudo-check ]]; then
        rm -f /usr/local/bin/cert-sudo-check
        echo "  /usr/local/bin/cert-sudo-check 已删除"
    fi
    # 清理 PAM
    if grep -q "cert-sudo-check" /etc/pam.d/sudo 2>/dev/null; then
        sed -i '/cert-operator/d;/cert-sudo-check/d' /etc/pam.d/sudo 2>/dev/null || true
        echo "  PAM 配置已清理"
    fi
    # 清理临时文件
    rm -f /tmp/.cert-sudo-sock
    rm -f /etc/sudoers.d/99-cert-operator 2>/dev/null || true
    echo "=== 卸载完成 ==="
    exit 0
fi

CA_PUB_FILE="${1:-/opt/ca_server/data/ca_key.pub}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== cert-operator sudo wrapper 部署 ==="
echo ""

# ---- 0. 检查 root ----
if [[ $(id -u) -ne 0 ]]; then
    echo "错误: 需要 root 权限运行此脚本"
    exit 1
fi

# ---- 1. 安装 cert-sudo-check ----
echo "[1/4] 安装 cert-sudo-check → /usr/local/bin/"
cp "$SCRIPT_DIR/cert-sudo-check" /usr/local/bin/cert-sudo-check
chmod +x /usr/local/bin/cert-sudo-check

# ---- 2. CA 公钥 ----
echo "[2/4] 检查 CA 公钥: $CA_PUB_FILE"
if [[ ! -f "$CA_PUB_FILE" ]]; then
    echo "  警告: CA 公钥不存在，cert-sudo-check 将始终失败"
    echo "  请从 CA 服务器获取: scp ca-server:/opt/ca_server/data/ca_key.pub $CA_PUB_FILE"
fi

# ---- 3. dpkg-divert + 安装 wrapper ----
echo "[3/4] 配置 dpkg-divert + 安装 sudo wrapper"

if [[ ! -f "/usr/bin/_sudo" ]]; then
    dpkg-divert --divert /usr/bin/_sudo --rename /usr/bin/sudo 2>/dev/null || true
    echo "  dpkg-divert: /usr/bin/sudo → /usr/bin/_sudo"
else
    echo "  dpkg-divert: 已配置（/usr/bin/_sudo 已存在）"
fi

cp "$SCRIPT_DIR/sudo-wrapper" /usr/bin/sudo
chmod 755 /usr/bin/sudo
echo "  wrapper: /usr/bin/sudo 已安装"

# verify
if [[ ! -x "/usr/bin/_sudo" ]]; then
    echo "  错误: /usr/bin/_sudo 不存在，dpkg-divert 可能失败"
    exit 1
fi

# ---- 4. PAM 配置 ----
echo "[4/4] 配置 PAM (/etc/pam.d/sudo)"
PAM_FILE=/etc/pam.d/sudo
if ! grep -q "cert-sudo-check" "$PAM_FILE" 2>/dev/null; then
    # 在 pam_unix 之前插入 cert-sudo-check
    if grep -q "^@include" "$PAM_FILE"; then
        sed -i '1i# cert-operator\n\
auth sufficient pam_exec.so /usr/local/bin/cert-sudo-check\n' "$PAM_FILE"
    else
        cat >> "$PAM_FILE" << 'PAM'
# cert-operator: certificate-based sudo
auth sufficient pam_exec.so /usr/local/bin/cert-sudo-check
PAM
    fi
    echo "  已添加 pam_exec.so cert-sudo-check"
else
    echo "  cert-sudo-check 已在 PAM 中配置"
fi

# ---- 完成 ----
echo ""
echo "=== 部署完成 ==="
echo ""
echo "验证:"
echo "  ls -la /usr/bin/sudo       # wrapper 脚本 (755)"
echo "  ls -la /usr/bin/_sudo      # 真正的 sudo (4755 setuid)"
echo "  cat /etc/pam.d/sudo        # 包含 cert-sudo-check"
echo "  dpkg-divert --list         # 查看 diversion"
echo ""
echo "卸载:"
echo "  sudo bash $0 --uninstall"
