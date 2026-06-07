#!/bin/bash
# =============================================================================
# cert-operator 服务端打包脚本
# 将 ca_server/ 源码打包为 release/ca-server.tar.gz
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/ca_server"
RELEASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/release"
VERSION="${1:-1.0.0}"
PACKAGE_NAME="ca-server-${VERSION}.tar.gz"

echo "📦 打包 cert-operator 服务端 v${VERSION}"
echo "   源目录: $CA_SERVER_DIR"
echo "   输出:   $RELEASE_DIR/$PACKAGE_NAME"

mkdir -p "$RELEASE_DIR"

# 打包，排除生成的文件
# 使用 --transform 重命名顶层目录，解压后为 ca-server/
tar -czf "$RELEASE_DIR/$PACKAGE_NAME" \
    --transform="s|^ca_server|ca-server|" \
    --exclude="ca_server/data" \
    --exclude="ca_server/dist" \
    --exclude="ca_server/__pycache__" \
    --exclude="ca_server/.venv" \
    -C "$(dirname "$CA_SERVER_DIR")" \
    ca_server/

echo ""
echo "✅ 打包完成: $RELEASE_DIR/$PACKAGE_NAME"
echo "   大小: $(du -h "$RELEASE_DIR/$PACKAGE_NAME" | cut -f1)"

# 同时复制 install.sh 到 release/
cp "$CA_SERVER_DIR/install.sh" "$RELEASE_DIR/install.sh"
chmod +x "$RELEASE_DIR/install.sh"
echo "   已同步 install.sh"
