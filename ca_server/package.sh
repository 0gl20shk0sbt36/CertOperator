#!/bin/bash
# =============================================================================
# cert-operator 服务端打包脚本
# 生成自解压安装脚本 release/ca-server-install.sh
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CA_SERVER_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/ca_server"
RELEASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)/release"
VERSION="${1:-1.1.0}"
OUTPUT="$RELEASE_DIR/ca-server-install.sh"

echo "📦 打包 cert-operator 服务端 v${VERSION}"
echo "   源目录: $CA_SERVER_DIR"
echo "   输出:   $OUTPUT"

mkdir -p "$RELEASE_DIR"

# 1. 打包源码（排除生成文件）
TMP_TAR=$(mktemp)
trap "rm -f '$TMP_TAR'" EXIT

tar -czf "$TMP_TAR" \
    --transform="s|^ca_server|ca-server|" \
    --exclude="ca_server/data" \
    --exclude="ca_server/dist" \
    --exclude="ca_server/__pycache__" \
    --exclude="ca_server/.venv" \
    --exclude="ca_server/*.v1" \
    -C "$(dirname "$CA_SERVER_DIR")" \
    ca_server/

TAR_SIZE=$(du -h "$TMP_TAR" | cut -f1)

# 2. 读取 install.sh 模板，追加 base64 编码的压缩包
{
    cat "$CA_SERVER_DIR/install.sh"
    echo ""
    echo "exit 0"
    echo "#__CERT_OP_ARCHIVE__"
    base64 < "$TMP_TAR"
} > "$OUTPUT"

chmod +x "$OUTPUT"
OUTPUT_SIZE=$(du -h "$OUTPUT" | cut -f1)

echo ""
echo "✅ 打包完成"
echo "   压缩包大小: $TAR_SIZE"
echo "   自解压脚本: $OUTPUT ($OUTPUT_SIZE)"
