"""
cert-operator plugin — 安全获取 SSH 子证书并连接目标服务器

工作流程:
  1. AI 调用 get_sub_cert(server, totp_code, cert_name, ...)
     → 用户从 TOTP App 获取一次性码
     → 插件用 HTTPS + mTLS 请求 CA 服务器
     → 服务器验证 TOTP，签发 SSH 子证书
     → 插件保存私钥到 ~/.hermes/certs/<name>，证书到 <name>-cert.pub
     → AI 看到证书保存路径

  2. AI 调用 ssh_with_cert(host, user, cert_path, ...)
     → SSH 自动发现同目录下的证书文件
     → 执行远程命令并返回结果

CA 服务器兼容: v1 (Python) / v2 (Go)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_CERTS_DIR = Path.home() / ".hermes" / "certs"
DEFAULT_TIMEOUT = 30
DEFAULT_CA_CERT = DEFAULT_CERTS_DIR / "ca-https-cert.pem"
DEFAULT_CLIENT_CERT = DEFAULT_CERTS_DIR / "client.cert"
DEFAULT_CLIENT_KEY = DEFAULT_CERTS_DIR / "client.key"
PLUGIN_VERSION = "3.0.0"

# ---------------------------------------------------------------------------
# HTTP 请求库：优先用 requests，回退到 urllib
# ---------------------------------------------------------------------------

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

if not HAS_REQUESTS:
    try:
        import urllib.request as _urllib_request
        import urllib.error as _urllib_error
        import ssl as _ssl
        HAS_URLLIB = True
    except ImportError:
        HAS_URLLIB = False
else:
    HAS_URLLIB = False

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


def _ensure_certs_dir() -> Path:
    path = DEFAULT_CERTS_DIR
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _validate_cert_name(name: str) -> str:
    """验证 cert_name 合法性，防止路径穿越。"""
    if not name or len(name) > 128:
        raise ValueError("cert_name 不能为空且不超过128字符")
    if "/" in name or "\\" in name or name in (".", "..") or name.startswith("."):
        raise ValueError(f"cert_name 包含非法字符或路径: '{name}'")
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_. ")
    if not all(c in allowed for c in name):
        raise ValueError(f"cert_name 只能包含字母、数字、空格和 -_. : '{name}'")
    return name.strip().replace(" ", "_")


def _safe_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def _save_ssh_cert(name: str, private_key: str, cert_content: str) -> tuple[str, str]:
    certs_dir = _ensure_certs_dir()
    safe_name = _safe_filename(name)
    key_path = certs_dir / safe_name
    key_path.write_text(private_key)
    key_path.chmod(0o600)
    cert_path = certs_dir / f"{safe_name}-cert.pub"
    cert_path.write_text(cert_content)
    cert_path.chmod(0o644)
    logger.info("SSH 私钥已保存: %s", key_path)
    logger.info("SSH 证书已保存: %s", cert_path)
    return str(key_path), str(cert_path)


def _check_version(server: str, ca_path: str, cc: str, ck: str) -> None:
    """检查服务端版本是否与插件版本一致。"""
    version_url = f"{server.rstrip('/')}/api/version"
    try:
        if HAS_REQUESTS:
            import requests
            ver_resp = requests.get(version_url, verify=ca_path, cert=(cc, ck), timeout=10)
            ver_resp.raise_for_status()
            sv = ver_resp.json().get("version", "")
        elif HAS_URLLIB:
            import ssl, urllib.request, json as _json
            ctx = ssl.create_default_context(cafile=ca_path)
            ctx.load_cert_chain(cc, ck)
            with urllib.request.urlopen(version_url, context=ctx, timeout=10) as vresp:
                sv = _json.loads(vresp.read()).get("version", "")
        else:
            return
        if sv and sv != PLUGIN_VERSION:
            raise RuntimeError(
                f"版本不匹配: 服务端 v{sv}, 插件 v{PLUGIN_VERSION}\n"
                "请使用相同版本的 cert-operator-plugin"
            )
    except RuntimeError:
        raise
    except Exception:
        pass  # 版本检查失败不影响后续（网络问题等）


def _request_cert(
    server: str,
    totp_code: str,
    ca_cert_path: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    group_name: Optional[str] = None,
    user_name: Optional[str] = None,
) -> dict[str, Any]:
    ca_path = ca_cert_path or str(DEFAULT_CA_CERT)
    cc = client_cert or str(DEFAULT_CLIENT_CERT)
    ck = client_key or str(DEFAULT_CLIENT_KEY)

    # 版本检查：确保服务端与插件版本一致
    _check_version(server, ca_path, cc, ck)

    url = f"{server.rstrip('/')}/api/get-cert"
    payload = {"totp": totp_code}
    if group_name:
        payload["group"] = group_name
    if user_name:
        payload["user"] = user_name

    if HAS_REQUESTS:
        return _request_cert_requests(url, payload, ca_path, cc, ck)
    elif HAS_URLLIB:
        return _request_cert_urllib(url, payload, ca_path, cc, ck)
    else:
        raise RuntimeError("需要 requests 或标准 urllib 支持")


def _request_cert_requests(
    url: str, payload: dict, ca_path: str, cc: str, ck: str
) -> dict[str, Any]:
    import requests
    headers = {"User-Agent": f"hermes-cert-operator/{PLUGIN_VERSION}"}
    resp = requests.post(
        url, json=payload, headers=headers,
        verify=ca_path, cert=(cc, ck),
        timeout=DEFAULT_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError(f"服务器返回格式异常: {resp.text[:500]}")
    if data.get("error"):
        raise ValueError(f"服务器返回错误: {data['error']}")
    return data


def _request_cert_urllib(
    url: str, payload: dict, ca_path: str, cc: str, ck: str
) -> dict[str, Any]:
    import ssl
    import urllib.request
    import urllib.error

    ctx = ssl.create_default_context(cafile=ca_path)
    # mTLS
    ctx.load_cert_chain(cc, ck)

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"hermes-cert-operator/{PLUGIN_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=DEFAULT_TIMEOUT) as resp:
            result = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        result = json.loads(e.read().decode())
        if result.get("error"):
            raise ValueError(f"服务器返回错误: {result['error']}")
        raise

    if not isinstance(result, dict):
        raise ValueError(f"服务器返回格式异常")
    if result.get("error"):
        raise ValueError(f"服务器返回错误: {result['error']}")
    return result


def _run_ssh(
    host: str, user: str, cert_path: str,
    port: int = 22, command: Optional[str] = None,
) -> dict[str, Any]:
    key_file = Path(cert_path)
    if not key_file.exists():
        return {"success": False, "output": f"私钥文件不存在: {cert_path}", "exit_code": -1}

    cert_file = key_file.with_name(f"{key_file.name}-cert.pub")
    has_cert = cert_file.exists()
    key_file.chmod(0o600)

    # 启动 ssh-agent 并将证书加载到其中
    # 目标服务器上的 cert-sudo-check 需要通过转发的 agent socket 验证证书
    agent_out = subprocess.run(
        ["ssh-agent", "-s"],
        capture_output=True, text=True, timeout=5,
    )
    agent_pid = None
    if agent_out.returncode == 0:
        for line in agent_out.stdout.split("\n"):
            if line.startswith("SSH_AUTH_SOCK="):
                sock = line.split("=", 1)[1].split(";", 1)[0].strip("\"'")
                os.environ["SSH_AUTH_SOCK"] = sock
            elif line.startswith("SSH_AGENT_PID="):
                pid_str = line.split("=", 1)[1].split(";", 1)[0].strip()
                try:
                    agent_pid = int(pid_str)
                except ValueError:
                    pass
    # 加载证书到 agent
    if agent_pid:
        subprocess.run(["ssh-add", str(key_file)], capture_output=True, timeout=5)

    ssh_cmd = [
        "ssh",
        "-A",  # agent forwarding: 必要，远程 cert-sudo-check 通过转发的 agent 验证证书
        "-i", str(key_file),
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={DEFAULT_CERTS_DIR}/known_hosts",
        "-o", "ConnectTimeout=15",
    ]
    target = f"{user}@{host}"

    try:
        if command:
            ssh_cmd.extend([target, command])
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)
            output = (result.stdout + result.stderr).strip()
            return {
                "success": result.returncode == 0,
                "output": output or "(无输出)",
                "exit_code": result.returncode,
            }
        else:
            cmd_str = " ".join(str(x) for x in ssh_cmd) + f" {target}"
            return {
                "success": True,
                "output": f"交互式 SSH 命令已生成:\n  {cmd_str}",
                "exit_code": 0,
                "command": cmd_str,
                "cert_auto_discovered": has_cert,
            }
    except subprocess.TimeoutExpired:
        return {"success": False, "output": "SSH 连接超时", "exit_code": -1}
    except FileNotFoundError:
        return {"success": False, "output": "未找到 ssh 命令，请安装 OpenSSH Client", "exit_code": -1}
    except Exception as e:
        return {"success": False, "output": f"SSH 执行失败: {type(e).__name__}: {e}", "exit_code": -1}
    finally:
        # 清理 agent
        if agent_pid:
            try:
                os.kill(agent_pid, 15)
            except OSError:
                pass
            os.environ.pop("SSH_AUTH_SOCK", None)
            os.environ.pop("SSH_AGENT_PID", None)


# ---------------------------------------------------------------------------
# 工具 schemas & handlers
# ---------------------------------------------------------------------------

def _call_server_api(server, endpoint, ca_cert_path=None, client_cert=None, client_key=None):
    """Call CA server API endpoint and return JSON."""
    ca_path = ca_cert_path or str(DEFAULT_CA_CERT)
    cc = client_cert or str(DEFAULT_CLIENT_CERT)
    ck = client_key or str(DEFAULT_CLIENT_KEY)
    url = f"{server.rstrip(chr(47))}/api/{endpoint}"
    if HAS_REQUESTS:
        import requests
        resp = requests.get(url, verify=ca_path, cert=(cc, ck), timeout=15)
        resp.raise_for_status()
        return json.dumps({"success": True, "data": resp.json()}, ensure_ascii=False, default=str)
    else:
        import ssl, urllib.request
        ctx = ssl.create_default_context(cafile=ca_path)
        ctx.load_cert_chain(cc, ck)
        with urllib.request.urlopen(url, context=ctx, timeout=15) as r:
            d = json.loads(r.read().decode())
            return json.dumps({"success": True, "data": d}, ensure_ascii=False, default=str)

def _handle_get_server_info(params=None, **kwargs):
    if params is None or not isinstance(params, dict): params = kwargs
    try:
        return _call_server_api(params.get("server",""), "info?level=full", params.get("ca_cert_path"), params.get("client_cert"), params.get("client_key"))
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)

def _handle_get_server_health(params=None, **kwargs):
    if params is None or not isinstance(params, dict): params = kwargs
    try:
        return _call_server_api(params.get("server",""), "health", params.get("ca_cert_path"), params.get("client_cert"), params.get("client_key"))
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)

def _handle_get_server_version(params=None, **kwargs):
    if params is None or not isinstance(params, dict): params = kwargs
    try:
        return _call_server_api(params.get("server",""), "version", params.get("ca_cert_path"), params.get("client_cert"), params.get("client_key"))
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)}, ensure_ascii=False)


SCHEMA_GET_SUB_CERT = {
    "name": "get_sub_cert",
    "description": (
        "【工作流第 1 步】从 CA 服务器获取 SSH 子证书。\n\n"
        "使用场景：用户需要通过 SSH 远程登录一台服务器（目标服务器），"
        "这台服务器信任 cert-operator CA 签发的 SSH 证书。\n\n"
        "执行流程：\n"
        "  1. 【告诉用户】请打开手机上的 TOTP 认证器 App（如 Google Authenticator），\n"
        "     查看当前 6 位一次性验证码，然后把验证码告诉我。\n"
        "  2. 用户提供验证码后，调用此工具传入 server 和 totp_code。\n"
        "  3. 服务器验证 TOTP 码，签发一张 SSH 子证书。\n"
        "  4. HTTPS 加密传输到本地，保存到 ~/.hermes/certs/ 目录。\n\n"
        "注意：\n"
        "  - cert_name 用于本地文件名标识，取完证书后返回值中有 cert_path。\n"
        "  - 下一步用 ssh_with_cert 工具连接目标服务器，传入该 cert_path。\n"
        "  - 如果 CA 服务器使用自签证书，需要 ca_cert_path 参数。\n"
        "  - 如果 CA 服务器启用了 mTLS，需要 client_cert 和 client_key。\n"
        "  - 如果服务器用组管理权限，传入 group_name 获取对应组的证书。\n"
        "  - user_name 指定证书允许登录的 SSH 用户名。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "server": {
                "type": "string",
                "description": "【必填】CA 服务器地址，格式 'https://<IP>:8443'。例如 'https://121.196.206.66:8443'",
            },
            "totp_code": {
                "type": "string",
                "description": "【必填】用户从 TOTP App 看到的当前 6 位验证码。如果用户还没提供，先问用户。格式：6位数字，如 '123456'",
            },
            "cert_name": {
                "type": "string",
                "description": "【必填】证书标识名称，用于本地文件名。建议用目标服务器的用途命名，如 'prod-db'、'web-server'、'dev-box'。最终文件保存为 ~/.hermes/certs/<cert_name>（私钥）和 ~/.hermes/certs/<cert_name>-cert.pub（证书）",
            },
            "ca_cert_path": {
                "type": "string",
                "description": "【选填】CA 服务器自签 HTTPS 证书的本地路径。默认 ~/.hermes/certs/ca-https-cert.pem。如果服务器使用自签证书，必须传此参数，否则 SSL 验证会失败。如果已有 deploy.sh 部署过客户端证书，通常不需要修改。",
            },
            "client_cert": {
                "type": "string",
                "description": "【选填】mTLS 客户端证书路径。默认 ~/.hermes/certs/client.cert。如果部署了客户端证书包（deploy.sh），此参数通常不需要修改。",
            },
            "client_key": {
                "type": "string",
                "description": "【选填】mTLS 客户端密钥路径。默认 ~/.hermes/certs/client.key。如果部署了客户端证书包（deploy.sh），此参数通常不需要修改。",
            },
            "group_name": {
                "type": "string",
                "description": "【选填】CA 服务器上的用户组名。服务器上的组控制证书是否有 sudo 权限、有效期等。不传则使用 default 组（需已配置 TOTP）。例如 admin（有 sudo）、operator（无 sudo）",
            },
            "user_name": {
                "type": "string",
                "description": "【选填】要登录的目标服务器 SSH 用户名。证书会签发为该用户，SSH 时只能用这个用户名登录。如果该用户不在组的允许列表中会失败。例如 root、ubuntu、ec2-user",
            },
        },
        "required": ["server", "totp_code", "cert_name"],
    },
}

SCHEMA_SSH_WITH_CERT = {
    "name": "ssh_with_cert",
    "description": (
        "【工作流第 2 步】使用上一步获取的 SSH 子证书连接目标服务器执行命令。\n\n"
        "使用场景：已经用 get_sub_cert 获取了证书，现在要 SSH 到目标服务器。\n\n"
        "执行流程：\n"
        "  1. 传入 host（目标服务器 IP）、user（SSH 用户名）、cert_path（上一步返回的 cert_path）。\n"
        "  2. SSH 自动发现 cert_path 同目录下的 <cert_path>-cert.pub 证书文件进行认证。\n"
        "  3. 如果传了 command 参数，执行命令并返回结果。\n"
        "  4. 如果不传 command，则生成 SSH 连接命令字符串供用户手动执行。\n\n"
        "注意：\n"
        "  - cert_path 必须是 get_sub_cert 返回的 cert_path 值。\n"
        "  - 如果希望执行交互式命令，可以不传 command 参数，让用户手动 SSH。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "【必填】目标服务器 IP 地址或主机名。例：'192.168.1.100'、'myserver.example.com'",
            },
            "user": {
                "type": "string",
                "description": "【必填】SSH 登录用户名。必须与 get_sub_cert 时传入的 user_name 一致（或由服务器默认决定）。例：'root'、'ubuntu'",
            },
            "cert_path": {
                "type": "string",
                "description": "【必填】SSH 私钥文件的完整路径。就是 get_sub_cert 返回结果中的 cert_path 字段值。例：'/home/user/.hermes/certs/web-server'。SSH 会自动读取同目录下的 web-server-cert.pub 作为证书。",
            },
            "command": {
                "type": "string",
                "description": "【选填】要在远程服务器上执行的命令。如果为空则只生成 SSH 连接命令字符串。例如想查看服务器信息：'uname -a && df -h'",
            },
            "port": {
                "type": "integer",
                "description": "【选填】SSH 端口号。默认 22。如果目标服务器使用非标端口需要指定。",
                "default": 22,
            },
        },
        "required": ["host", "user", "cert_path"],
    },
}


def _handle_get_sub_cert(params=None, **kwargs) -> str:
    if params is None or not isinstance(params, dict):
        params = kwargs
    try:
        server = params.get("server", "").strip()
        totp_code = params.get("totp_code", "").strip()
        cert_name = params.get("cert_name", "").strip()

        if not server:
            raise ValueError("server 不能为空，请输入 CA 服务器地址")
        if not totp_code:
            raise ValueError("totp_code 不能为空，请先向用户索取 TOTP 验证码")
        if not cert_name:
            raise ValueError("cert_name 不能为空")
        if len(totp_code) != 6 or not totp_code.isdigit():
            raise ValueError(f"TOTP 码必须是 6 位数字，收到: '{totp_code}'")
        cert_name = _validate_cert_name(cert_name)

        ca_cert_path = params.get("ca_cert_path") or None
        client_cert = params.get("client_cert") or None
        client_key = params.get("client_key") or None
        group_name = params.get("group_name") or None
        user_name = params.get("user_name") or None

        data = _request_cert(server, totp_code, ca_cert_path, client_cert, client_key, group_name, user_name)
        ssh_private_key = data.get("ssh_private_key", "")
        ssh_cert = data.get("ssh_cert", "")
        if not ssh_private_key:
            return json.dumps({"success": False, "error": "服务器响应中未包含 SSH 私钥"}, ensure_ascii=False)
        if not ssh_cert:
            return json.dumps({"success": False, "error": "服务器响应中未包含 SSH 证书"}, ensure_ascii=False)

        key_path, cert_path = _save_ssh_cert(cert_name, ssh_private_key, ssh_cert)
        result = {
            "success": True,
            "cert_path": key_path,
            "cert_name": cert_name,
            "message": (
                f"✅ SSH 子证书已获取\n"
                f"   私钥: {key_path}\n"
                f"   证书: {cert_path}\n"
                f"   SSH 会自动使用同目录证书\n\n"
                f"现在可以使用 ssh_with_cert 工具 SSH 到目标服务器"
            ),
        }
        for field in ("serial", "expires_at"):
            if field in data:
                result[field] = data[field]
        return json.dumps(result, ensure_ascii=False)

    except Exception as e:
        logger.exception("get_sub_cert 失败")
        msg = str(e)
        hint = ""
        if "SSL" in type(e).__name__ or "ssl" in msg.lower():
            hint = " — 请确认 ca_cert_path 正确"
        if "Connection" in type(e).__name__:
            hint = " — 请检查服务器地址和网络"
        return json.dumps({"success": False, "error": f"{msg}{hint}"}, ensure_ascii=False)


def _handle_ssh_with_cert(params=None, **kwargs) -> str:
    if params is None or not isinstance(params, dict):
        params = kwargs
    try:
        host = params.get("host", "").strip()
        user = params.get("user", "").strip()
        cert_path = params.get("cert_path", "").strip()
        command = params.get("command")
        raw_port = params.get("port", 22)
        if isinstance(raw_port, str):
            raw_port = raw_port.strip()
        try:
            port = int(raw_port)
        except (ValueError, TypeError):
            raise ValueError(f"端口号必须为数字，收到: '{raw_port}'")
        if port < 1 or port > 65535:
            raise ValueError(f"端口号超出范围 (1-65535): {port}")
        if not host:
            raise ValueError("host 不能为空，请输入目标服务器地址")
        if not user:
            raise ValueError("user 不能为空，请输入 SSH 用户名")
        if not cert_path:
            raise ValueError("cert_path 不能为空，请先调用 get_sub_cert 获取证书")
        if not Path(cert_path).exists():
            raise ValueError(f"证书私钥文件不存在: {cert_path}，请先调用 get_sub_cert 获取证书")
        result = _run_ssh(host, user, cert_path, port, command)
        return json.dumps(result, ensure_ascii=False, default=str)
    except Exception as e:
        logger.exception("ssh_with_cert 失败")
        return json.dumps({"success": False, "output": f"SSH 执行失败: {e}", "exit_code": -1}, ensure_ascii=False)


# ---------------------------------------------------------------------------
# 插件注册
# ---------------------------------------------------------------------------


def register(ctx) -> None:
    """注册 cert-operator 的所有工具。"""
    ctx.register_tool(
        name="get_sub_cert", toolset="custom",
        schema=SCHEMA_GET_SUB_CERT, handler=_handle_get_sub_cert,
        description="🔐 【工作流第1步】获取TOTP码→CA签发SSH子证书→保存到本地。先问用户要TOTP验证码，返回的cert_path用于下一步ssh_with_cert",
        emoji="🔐",
    )
    ctx.register_tool(
        name="ssh_with_cert", toolset="custom",
        schema=SCHEMA_SSH_WITH_CERT, handler=_handle_ssh_with_cert,
        description="🔑 【工作流第2步】用get_sub_cert获取的证书SSH登录目标服务器。传入cert_path（上一步返回值）+host+user+command",
        emoji="🔑",
    )
    ctx.register_tool(
        name="get_server_info", toolset="custom",
        schema={"name":"get_server_info","description":"查询CA服务器信息（组配置、CA公钥指纹等）",
                "parameters":{"type":"object","properties":{"server":{"type":"string","description":"【必填】CA服务器地址"}},"required":["server"]}},
        handler=_handle_get_server_info, emoji="ℹ️",
    )
    ctx.register_tool(
        name="get_server_health", toolset="custom",
        schema={"name":"get_server_health","description":"检查CA服务器是否在线",
                "parameters":{"type":"object","properties":{"server":{"type":"string","description":"【必填】CA服务器地址"}},"required":["server"]}},
        handler=_handle_get_server_health, emoji="💚",
    )
    ctx.register_tool(
        name="get_server_version", toolset="custom",
        schema={"name":"get_server_version","description":"查询CA服务器版本号",
                "parameters":{"type":"object","properties":{"server":{"type":"string","description":"【必填】CA服务器地址"}},"required":["server"]}},
        handler=_handle_get_server_version, emoji="📌",
    )
