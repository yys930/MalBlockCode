# backend/agent/mcp_enforcer_client.py
import asyncio
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


@dataclass
class MCPServerParams:
    command: str
    args: list[str]


class MCPEnforcerClient:
    """
    关键点：
    - 内部启动一个后台线程 + 专用 event loop
    - stdio_client / ClientSession 的 enter/exit 全在同一个 loop 中完成
    - 同步方法通过 run_coroutine_threadsafe 调用异步逻辑
    """

    def __init__(self, server_params: MCPServerParams):
        self.server_params = server_params

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

        self._cm = None  # async context manager returned by stdio_client
        self._session: Optional[ClientSession] = None

        self._started = False

    # ---------- loop/thread lifecycle ----------

    def start(self) -> None:
        if self._started:
            return
        self._started = True

        self._loop = asyncio.new_event_loop()

        def _run_loop():
            asyncio.set_event_loop(self._loop)
            self._loop.run_forever()

        self._thread = threading.Thread(target=_run_loop, daemon=True)
        self._thread.start()

        # 在 loop 中完成连接初始化（可延迟到第一次 call_tool，但这里先连上更稳）
        self._run_sync(self._connect())

    def close(self) -> None:
        if not self._started:
            return
        try:
            self._run_sync(self._aclose())
        finally:
            assert self._loop is not None
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread:
                self._thread.join(timeout=2)
            self._started = False

    def _run_sync(self, coro):
        """把 coroutine 丢到后台 loop 里跑，并同步等待结果。"""
        assert self._loop is not None
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result()

    # ---------- MCP core ----------

    async def _connect(self) -> None:
        if self._session:
            return

        sp = StdioServerParameters(
            command=self.server_params.command,
            args=self.server_params.args,
        )

        self._cm = stdio_client(sp)
        read, write = await self._cm.__aenter__()

        self._session = ClientSession(read, write)
        await self._session.__aenter__()
        await self._session.initialize()

    async def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        await self._connect()
        assert self._session is not None
        res = await self._session.call_tool(name, arguments=arguments)
        return self._normalize_tool_response(res.model_dump())

    async def _aclose(self) -> None:
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None
        if self._cm:
            await self._cm.__aexit__(None, None, None)
            self._cm = None

    # ---------- public sync tool API ----------

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self._started:
            self.start()
        return self._run_sync(self._call_tool(name, arguments))

    def block_ip(self, ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_tool("block_ip", {"ip": ip, "ttl_sec": int(ttl_sec), "reason": reason, "meta": meta})

    def rate_limit_ip(self, ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_tool("rate_limit_ip", {"ip": ip, "ttl_sec": int(ttl_sec), "reason": reason, "meta": meta})

    def watch_ip(self, ip: str, ttl_sec: int, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_tool("watch_ip", {"ip": ip, "ttl_sec": int(ttl_sec), "reason": reason, "meta": meta})

    def unblock_ip(self, ip: str, reason: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_tool("unblock_ip", {"ip": ip, "reason": reason, "meta": meta})

    def list_blocked(self) -> Dict[str, Any]:
        return self.call_tool("list_blocked", {})

    @staticmethod
    def _normalize_tool_response(raw: Dict[str, Any]) -> Dict[str, Any]:
        if raw.get("isError") is True:
            return {"ok": False, "mcp_raw": raw, "error": "mcp tool call returned isError=true"}

        content = raw.get("content")
        if not isinstance(content, list):
            return raw

        for item in content:
            if not isinstance(item, dict):
                continue

            text = item.get("text")
            if not isinstance(text, str):
                continue

            text = text.strip()
            if not text:
                continue

            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue

            if isinstance(parsed, dict):
                parsed.setdefault("mcp_raw", raw)
                return parsed

        return raw
