# backend/agent/mcp_enforcer_server.py
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional
from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from path_utils import resolve_project_path
from mcp.server.fastmcp import FastMCP

load_dotenv()

mcp = FastMCP("MalBlockEnforcer", json_response=True)

# nftables object names. Defaults must stay aligned with init_nftables.sh.
NFT_TABLE = os.environ.get("NFT_TABLE", "inet")
NFT_FAMILY_TABLE = os.environ.get("NFT_FAMILY_TABLE", "filter")
NFT_SET = os.environ.get("NFT_SET", "blocklist_v4")
NFT_RATE_LIMIT_SET = os.environ.get("NFT_RATE_LIMIT_SET", "ratelimit_v4")
NFT_WATCH_SET = os.environ.get("NFT_WATCH_SET", "watchlist_v4")

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
_audit_path_env = os.environ.get("ENFORCER_AUDIT_PATH", "")
AUDIT_PATH = str(resolve_project_path(_audit_path_env)) if _audit_path_env else ""


def audit(obj: Dict[str, Any]) -> None:
    if not AUDIT_PATH:
        return
    rec = {"ts": int(time.time()), **obj}
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def run_cmd(cmd: list[str]) -> Dict[str, Any]:
    if DRY_RUN:
        return {"ok": True, "dry_run": True, "cmd": cmd}
    try:
        p = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return {"ok": True, "dry_run": False, "cmd": cmd, "stdout": p.stdout}
    except subprocess.CalledProcessError as e:
        return {"ok": False, "dry_run": False, "cmd": cmd, "stderr": e.stderr, "error": str(e)}


def _list_set_cmd(set_name: str) -> list[str]:
    return ["sudo", "nft", "list", "set", f"{NFT_TABLE} {NFT_FAMILY_TABLE}", set_name]


def _is_ip_in_set(ip: str, set_name: str) -> Dict[str, Any]:
    out = run_cmd(_list_set_cmd(set_name))
    if not out.get("ok"):
        return {"ok": False, "blocked": False, "source": out}
    stdout = out.get("stdout", "")
    return {"ok": True, "blocked": ip in stdout, "source": out}


def _add_ip_to_set(ip: str, ttl_sec: int, set_name: str, action: str, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    state = _is_ip_in_set(ip, set_name)
    if state.get("ok") and state.get("blocked"):
        out = {
            "ok": True,
            "dry_run": DRY_RUN,
            "action": action,
            "ip": ip,
            "ttl_sec": int(ttl_sec),
            "reason": reason,
            "meta": meta,
            "set_name": set_name,
            "already_present": True,
        }
        audit(out)
        return out
    cmd = [
        "sudo", "nft", "add", "element",
        f"{NFT_TABLE} {NFT_FAMILY_TABLE}", set_name,
        f"{{ {ip} timeout {int(ttl_sec)}s }}"
    ]
    out = run_cmd(cmd)
    out.update({
        "action": action,
        "ip": ip,
        "ttl_sec": int(ttl_sec),
        "reason": reason,
        "meta": meta,
        "set_name": set_name,
    })
    audit(out)
    return out


@mcp.tool()
def block_ip(ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Block an IP using nft set element with timeout.
    Requires the configured block set to exist, default: inet filter blocklist_v4.
    """
    return _add_ip_to_set(ip, ttl_sec, NFT_SET, "block_ip", reason, meta)


@mcp.tool()
def rate_limit_ip(ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add an IP into a dedicated nft set used by pre-configured rate-limit rules.
    Requires the configured rate-limit set to exist, default: inet filter ratelimit_v4.
    """
    return _add_ip_to_set(ip, ttl_sec, NFT_RATE_LIMIT_SET, "rate_limit_ip", reason, meta)


@mcp.tool()
def watch_ip(ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add an IP into a dedicated nft set used by pre-configured watch/log rules.
    Requires the configured watch set to exist, default: inet filter watchlist_v4.
    """
    return _add_ip_to_set(ip, ttl_sec, NFT_WATCH_SET, "watch_ip", reason, meta)


@mcp.tool()
def unblock_ip(ip: str, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    cmd = [
        "sudo", "nft", "delete", "element",
        f"{NFT_TABLE} {NFT_FAMILY_TABLE}", NFT_SET,
        f"{{ {ip} }}"
    ]
    out = run_cmd(cmd)
    out.update({"action": "unblock_ip", "ip": ip, "reason": reason, "meta": meta})
    audit(out)
    return out


@mcp.tool()
def list_blocked() -> Dict[str, Any]:
    cmd = _list_set_cmd(NFT_SET)
    out = run_cmd(cmd)
    out.update({"action": "list_blocked"})
    audit(out)
    return out


if __name__ == "__main__":
    # stdio transport：MCP client 会以子进程方式启动本 server
    mcp.run()
