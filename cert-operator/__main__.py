"""CLI entry point for cert-operator.

Usage::

    python3 -m cert-operator get-cert <server> <totp_code> <cert_name>

    python3 -m cert-operator ssh <host> <user> <cert_path> [command]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .client import get_sub_cert, ssh_with_cert


def _get_cert_default(name: str) -> str:
    """Default path under ~/.hermes/certs/."""
    return str(Path.home() / ".hermes" / "certs" / name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="cert-operator — TOTP + mTLS SSH 证书客户端",
    )
    sub = parser.add_subparsers(dest="command", title="命令")

    # get-cert
    p_get = sub.add_parser("get-cert", help="从 CA 服务器获取 SSH 子证书")
    p_get.add_argument("server", help="CA 服务器地址，如 https://ca.example.com:8443")
    p_get.add_argument("totp_code", help="6 位 TOTP 验证码")
    p_get.add_argument("cert_name", help="证书文件名标识，如 prod-server")
    p_get.add_argument("--ca-cert",
                       default=_get_cert_default("ca-https-cert.pem"),
                       help="CA HTTPS 证书路径（默认 ~/.hermes/certs/ca-https-cert.pem）")
    p_get.add_argument("--client-cert",
                       default=_get_cert_default("client.cert"),
                       help="mTLS 客户端证书路径（默认 ~/.hermes/certs/client.cert）")
    p_get.add_argument("--client-key",
                       default=_get_cert_default("client.key"),
                       help="mTLS 客户端密钥路径（默认 ~/.hermes/certs/client.key）")

    # ssh
    p_ssh = sub.add_parser("ssh", help="使用 SSH 证书登录目标服务器")
    p_ssh.add_argument("host", help="目标服务器地址")
    p_ssh.add_argument("user", help="SSH 用户名")
    p_ssh.add_argument("cert_path", help="私钥路径，如 ~/.hermes/certs/prod-server")
    p_ssh.add_argument("command", nargs="?", default=None, help="要执行的命令（可选）")
    p_ssh.add_argument("--port", type=int, default=22, help="SSH 端口（默认 22）")
    p_ssh.add_argument("--expires-at", help="证书过期时间 ISO 8601（可选）")
    p_ssh.add_argument("--host-key", help="目标服务器主机密钥指纹（可选）")

    args = parser.parse_args()

    if args.command == "get-cert":
        try:
            result = get_sub_cert(
                server=args.server,
                totp_code=args.totp_code,
                cert_name=args.cert_name,
                ca_cert_path=args.ca_cert,
                client_cert=args.client_cert,
                client_key=args.client_key,
            )
            print(f"✅ 证书已保存到: {result['cert_path']}")
            print(f"   序列号: {result['serial']}")
            print(f"   过期:   {result['expires_at']}")
        except Exception as e:
            print(f"❌ {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "ssh":
        try:
            result = ssh_with_cert(
                host=args.host,
                user=args.user,
                cert_path=args.cert_path,
                command=args.command,
                port=args.port,
                expires_at=args.expires_at,
                host_key=args.host_key,
            )
            if result["success"]:
                print(result["output"])
            else:
                print(f"❌ SSH 执行失败（exit code {result['exit_code']}）")
                print(result["output"])
                sys.exit(result["exit_code"])
        except Exception as e:
            print(f"❌ {e}", file=sys.stderr)
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
