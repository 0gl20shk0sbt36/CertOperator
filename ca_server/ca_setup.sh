#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"

echo "📦 安装依赖..."
pip3 install -r requirements.txt

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
echo "  # 2. 启动 HTTPS 服务"
echo "  python3 ca_server.py serve"
echo ""
echo "  # 3. 部署 CA 公钥到目标服务器"
echo "  python3 ca_server.py pubkey"
echo ""
echo "  # 4. 将 HTTPS 证书分发给客户端"
echo "  scp data/https_cert.pem user@client:~/.hermes/certs/ca-https-cert.pem"
