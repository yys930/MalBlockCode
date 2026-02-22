# backend/agent/mcp_enforcer_server.py
import json
import os
import subprocess
import time
from typing import Any, Dict, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MalBlockEnforcer", json_response=True)

# nft 配置（按你实际表/set 名修改）
NFT_TABLE = os.environ.get("NFT_TABLE", "inet")
NFT_FAMILY_TABLE = os.environ.get("NFT_FAMILY_TABLE", "filter")
NFT_SET = os.environ.get("NFT_SET", "blocklist_v4")

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
AUDIT_PATH = os.environ.get("ENFORCER_AUDIT_PATH", "")


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


@mcp.tool()
def block_ip(ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Block an IP using nft set element with timeout.
    Requires nft set exists: inet filter blocked_v4
    """
    cmd = [
        "sudo", "nft", "add", "element",
        f"{NFT_TABLE} {NFT_FAMILY_TABLE}", NFT_SET,
        f"{{ {ip} timeout {int(ttl_sec)}s }}"
    ]
    out = run_cmd(cmd)
    out.update({"action": "block_ip", "ip": ip, "ttl_sec": int(ttl_sec), "reason": reason, "meta": meta})
    audit(out)
    return out


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
    cmd = ["sudo", "nft", "list", "set", f"{NFT_TABLE} {NFT_FAMILY_TABLE}", NFT_SET]
    out = run_cmd(cmd)
    out.update({"action": "list_blocked"})
    audit(out)
    return out


if __name__ == "__main__":
    # stdio transport：MCP client 会以子进程方式启动本 server
    mcp.run()