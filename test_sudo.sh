#!/bin/bash
# cert-operator SSH + sudo 测试脚本
# 在 CA 服务器上直接运行，无需外部机器
set -euo pipefail

TOTP="${1:-}"
if [[ -z "$TOTP" ]]; then
    echo "用法: bash test_sudo.sh <aiuser 的 TOTP 码>"
    echo "先跑 cert-operator groups totp aiuser verify 拿到码再传"
    exit 1
fi

echo "=== 1. 获取证书 ==="
curl -sk --cacert ~/.hermes/certs/ca-https-cert.pem \
  --cert ~/.hermes/certs/client.cert \
  --key ~/.hermes/certs/client.key \
  https://localhost:8443/api/get-cert \
  -H "Content-Type: application/json" \
  -d "{\"totp\":\"$TOTP\",\"group\":\"aiuser\",\"user\":\"aibot\"}" \
  -o /tmp/cert_test.json

python3 -c "
import json
with open('/tmp/cert_test.json') as f:
    d = json.load(f)
if not d.get('success'):
    print('❌ 获取证书失败:', d.get('error'))
    exit(1)
for sfx, key in [('_key','ssh_private_key'),('_cert.pub','ssh_cert')]:
    with open('/tmp/test'+sfx,'w') as f: f.write(d[key])
import os; os.chmod('/tmp/test_key',0o600)
print('✅ 证书获取成功, serial='+str(d['serial']))
"

echo ""
echo "=== 2. 证书内容 ==="
ssh-keygen -L -f /tmp/test_cert.pub 2>/dev/null | grep -E "Type|Valid|Principals|sudo"

echo ""
echo "=== 3. SSH 证书登录测试 ==="
ssh -i /tmp/test_key -o StrictHostKeyChecking=no \
  aibot@localhost "echo '  登录成功: '; whoami" 2>&1 && \
  echo "  ✅ SSH 登录成功" || echo "  ❌ SSH 登录失败"

echo ""
echo "=== 4. sudo 测试 ==="
eval $(ssh-agent -s) > /dev/null
ssh-add /tmp/test_key 2>&1 | tail -1
ssh -o StrictHostKeyChecking=no -A \
  aibot@localhost "echo '  sudo 结果:'; sudo -n whoami 2>&1" 2>&1 && \
  echo "  ✅ sudo 成功" || echo "  ❌ sudo 失败"
kill $SSH_AGENT_PID 2>/dev/null

echo ""
echo "=== 完成 ==="
rm -f /tmp/cert_test.json /tmp/test_key /tmp/test_cert.pub
