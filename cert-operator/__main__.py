"""CLI entry point for cert-operator.

Usage::

    python3 -m cert-operator get-cert <server> <totp_code> <cert_name>
    python3 -m cert-operator ssh <host> <user> <cert_path>
    python3 -m cert-operator version
    python3 -m cert-operator deploy
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .client import get_sub_cert, ssh_with_cert
from . import __version__


def _hermes_dir() -> Path:
    return Path.home() / ".hermes" / "certs"


def _default_cert(name: str) -> str:
    return str(_hermes_dir() / name)


def _get_cert_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "get-cert",
        help="从 CA 服务器获取 SSH 子证书",
        description=(
            "通过 TOTP + mTLS 双层认证，经 HTTPS 从 CA 服务器获取 SSH 子证书。"
            "需要预先部署客户端证书（ca-https-cert.pem, client.cert, client.key）"
            "至 ~/.hermes/certs/ 目录。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("server", help="CA 服务器地址，如 https://ca.example.com:8443")
    p.add_argument("totp_code", help="6 位 TOTP 验证码")
    p.add_argument("cert_name", help="证书文件名标识，如 prod-server")
    p.add_argument("--ca-cert",
                   default=_default_cert("ca-https-cert.pem"),
                   help="CA HTTPS 证书路径（默认 ~/.hermes/certs/ca-https-cert.pem）")
    p.add_argument("--client-cert",
                   default=_default_cert("client.cert"),
                   help="mTLS 客户端证书路径（默认 ~/.hermes/certs/client.cert）")
    p.add_argument("--client-key",
                   default=_default_cert("client.key"),
                   help="mTLS 客户端密钥路径（默认 ~/.hermes/certs/client.key）")
    p.add_argument("--group", "-g",
                   default=None,
                   help="用户组名（默认使用 default 组）")
    p.add_argument("--user", "-u",
                   default=None,
                   help="用户名（默认由服务端决定）")


def _ssh_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "ssh",
        help="使用 SSH 证书登录目标服务器",
        description=(
            "使用 SSH 证书登录目标服务器。OpenSSH 自动发现同目录下的 "
            "<cert_path>-cert.pub 证书文件。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("host", help="目标服务器地址")
    p.add_argument("user", help="SSH 用户名")
    p.add_argument("cert_path", help="私钥路径，如 ~/.hermes/certs/prod-server")
    p.add_argument("command", nargs="?", default=None, help="要执行的命令（可选，省略则开启登录 shell）")
    p.add_argument("--port", type=int, default=22, help="SSH 端口（默认 22）")
    p.add_argument("--expires-at", help="证书过期时间 ISO 8601（可选，连接前检查）")
    p.add_argument("--host-key", help="目标服务器主机密钥指纹（可选）")


def _deploy_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "deploy",
        help="部署客户端证书到 ~/.hermes/certs/",
        description=(
            "将 CA 服务器签发的客户端证书部署到本地 ~/.hermes/certs/ 目录。"
            "需要提供 deploy.sh 脚本所在目录，或从标准位置读取。"
        ),
    )
    p.add_argument("deploy_script",
                   nargs="?",
                   default="./deploy.sh",
                   help="deploy.sh 路径（默认 ./deploy.sh）")


def _cmd_get_cert(args: argparse.Namespace) -> None:
    try:
        result = get_sub_cert(
            server=args.server,
            totp_code=args.totp_code,
            cert_name=args.cert_name,
            ca_cert_path=args.ca_cert,
            client_cert=args.client_cert,
            client_key=args.client_key,
            group_name=args.group,
            user_name=args.user,
        )
        print(f"✅ 证书已保存")
        print(f"   私钥: {result['cert_path']}")
        cert_file = Path(result['cert_path']).parent / f"{args.cert_name}-cert.pub"
        print(f"   证书: {cert_file}")
        if result.get("serial"):
            print(f"   序列号: {result['serial']}")
        if result.get("expires_at"):
            print(f"   过期:   {result['expires_at']}")
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)


def _cmd_ssh(args: argparse.Namespace) -> None:
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
            if result["output"] and result["output"] != "(no output)":
                print(result["output"])
        else:
            print(result["output"], file=sys.stderr)
            sys.exit(result["exit_code"])
    except Exception as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)


def _cmd_deploy(args: argparse.Namespace) -> None:
    script = Path(args.deploy_script).expanduser()
    if not script.is_file():
        print(f"❌ 部署脚本不存在：{script}", file=sys.stderr)
        print(f"   请从 CA 服务器获取：scp user@ca-server:~/deploy.sh .", file=sys.stderr)
        sys.exit(1)
    print(f"📦 运行部署脚本: {script}")
    import subprocess
    rc = subprocess.call(["bash", str(script)])
    if rc == 0:
        print(f"✅ 客户端证书部署完成")
    else:
        print(f"❌ 部署脚本执行失败（exit code {rc}）", file=sys.stderr)
        sys.exit(rc)


def _cmd_version() -> None:
    print(f"cert-operator v{__version__}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cert-operator",
        description="cert-operator — TOTP + mTLS 双层认证 SSH 证书客户端",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", title="命令")

    _get_cert_parser(sub)
    _ssh_parser(sub)
    _deploy_parser(sub)
    sub.add_parser("version", help="显示版本号")

    args = parser.parse_args()

    if args.command == "get-cert":
        _cmd_get_cert(args)
    elif args.command == "ssh":
        _cmd_ssh(args)
    elif args.command == "deploy":
        _cmd_deploy(args)
    elif args.command == "version":
        _cmd_version()
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
