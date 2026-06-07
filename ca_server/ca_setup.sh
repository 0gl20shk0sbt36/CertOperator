#!/bin/bash
# =============================================================================
# cert-operator 服务端快速设置（开发环境用）
# 生产环境请使用: bash ca_server/package.sh → scp release/ca-server-install.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "📦 安装依赖..."
pip3 install --break-system-packages -r requirements.txt
pip3 install --break-system-packages "requests>=2.31"

echo ""
echo "🔨 初始化 CA 密钥和证书..."
python3 ca_server.py init

echo ""
echo "============================================"
echo "  CA 服务器初始化完成！"
echo "============================================"
echo ""
echo "  # 1. 配置 TOTP（生成 Secret + 扫码绑定）"
echo "  python3 ca_server.py totp"
echo ""
echo "  # 2. 启动 HTTPS 服务（mTLS 双向验证）"
echo "  python3 ca_server.py serve"
echo ""
echo "  # 3. 部署 CA 公钥到目标服务器"
echo "  python3 ca_server.py pubkey"
echo ""
echo "  # 4. 客户端部署包"
echo "  scp data/dist/deploy.sh user@client:~/"
echo "  # 客户端运行: bash ~/deploy.sh"
