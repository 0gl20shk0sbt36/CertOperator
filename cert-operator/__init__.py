"""cert-operator — TOTP-gated SSH certificate client."""

from __future__ import annotations

__version__ = "1.2.0"

from .tools import (
    GET_SUB_CERT_SCHEMA,
    SSH_WITH_CERT_SCHEMA,
    _handle_get_sub_cert,
    _handle_ssh_with_cert,
)


def register(ctx) -> None:
    """Register get_sub_cert and ssh_with_cert tools."""

    ctx.register_tool(
        name="get_sub_cert",
        toolset="custom",
        schema=GET_SUB_CERT_SCHEMA,
        handler=_handle_get_sub_cert,
        description="通过 TOTP 从 CA 服务器获取 SSH 子证书（需要持有 CA HTTPS 自签证书）",
        emoji="🔐",
    )

    ctx.register_tool(
        name="ssh_with_cert",
        toolset="custom",
        schema=SSH_WITH_CERT_SCHEMA,
        handler=_handle_ssh_with_cert,
        description="使用 SSH 证书登录目标服务器并执行命令",
        emoji="🔑",
    )
