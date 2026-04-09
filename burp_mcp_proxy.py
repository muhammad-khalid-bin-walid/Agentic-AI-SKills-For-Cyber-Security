#!/usr/bin/env python3
"""
Burp Suite MCP Proxy Server
============================
Launches the Burp Suite MCP server as a subprocess (stdio transport),
discovers its tools, and re-exposes them to Claude via its own stdio
MCP interface.

Usage:
    python burp_mcp_proxy.py --burp-cmd "java -jar C:\\Users\\rashed\\Downloads\\mcp-proxy.jar"

Or set via environment variable:
    BURP_MCP_CMD="java -jar /path/to/mcp-proxy.jar" python burp_mcp_proxy.py

Configuration (edit defaults below or use CLI args / env vars):
    BURP_MCP_CMD   - Command to launch the Burp MCP server
    PROXY_LOG      - Path to log file (default: burp_mcp_proxy.log)
"""

import sys
import os
import json
import asyncio
import logging
import argparse
import shlex
from typing import Any, Optional

# ---- Constants ----
DEFAULT_BURP_CMD = "java -jar mcp-proxy.jar"
DEFAULT_LOG_FILE = "burp_mcp_proxy.log"
MCP_PROTOCOL_VERSION = "2024-11-05"
READ_BUFFER_SIZE = 4096
MCP_RPC_TIMEOUT = 30
HEADER_ENCODING = "utf-8"
JSON_RPC_VERSION = "2.0"

# ---- Logging setup ----
def _setup_logging() -> logging.Logger:
    """Configure logging to file with ISO timestamp."""
    log_file = os.environ.get("PROXY_LOG", DEFAULT_LOG_FILE)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.FileHandler(log_file)],
    )
    return logging.getLogger("burp_mcp_proxy")

log = _setup_logging()

# ---- JSON-RPC helpers ----

def _frame_message(data: str) -> bytes:
    """Frame a JSON string with Content-Length header for LSP/MCP transport."""
    encoded = data.encode("utf-8")
    return f"Content-Length: {len(encoded)}\r\n\r\n".encode() + encoded


def make_request(id_: Any, method: str, params: Optional[dict] = None) -> bytes:
    """Create a JSON-RPC 2.0 request message."""
    msg = {"jsonrpc": JSON_RPC_VERSION, "id": id_, "method": method}
    if params is not None:
        msg["params"] = params
    return _frame_message(json.dumps(msg))


def make_response(id_: Any, result: Any) -> bytes:
    """Create a JSON-RPC 2.0 response message."""
    msg = {"jsonrpc": JSON_RPC_VERSION, "id": id_, "result": result}
    return _frame_message(json.dumps(msg))


def make_error(id_: Any, code: int, message: str) -> bytes:
    """Create a JSON-RPC 2.0 error message."""
    msg = {"jsonrpc": JSON_RPC_VERSION, "id": id_, "error": {"code": code, "message": message}}
    return _frame_message(json.dumps(msg))


def make_notification(method: str, params: Optional[dict] = None) -> bytes:
    """Create a JSON-RPC 2.0 notification (request with no id)."""
    msg = {"jsonrpc": JSON_RPC_VERSION, "method": method}
    if params is not None:
        msg["params"] = params
    return _frame_message(json.dumps(msg))


# ---- Helper functions ----

def _parse_headers(data: bytes) -> tuple[dict[str, str], int]:
    """Parse MCP/LSP headers and return (headers dict, content length)."""
    headers = {}
    try:
        for line in data.decode(HEADER_ENCODING).split("\r\n"):
            line = line.strip()
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
    except (UnicodeDecodeError, ValueError) as e:
        log.warning("Failed to parse headers: %s", e)
        return {}, 0
    
    content_length = int(headers.get("content-length", 0))
    return headers, content_length


# ---- Burp subprocess wrapper ----

class BurpMCPClient:
    """Manages the Burp MCP subprocess and synchronous request/response."""

    def __init__(self, cmd: str):
        """Initialize with command to launch Burp MCP server.
        
        Args:
            cmd: Shell command to launch the Burp MCP server.
        """
        self.cmd = cmd
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._id_counter = 0
        self._pending: dict[Any, asyncio.Future] = {}
        self._initialized = False
        self._tools: list[dict] = []

    def _next_id(self) -> int:
        """Generate next JSON-RPC message ID."""
        self._id_counter += 1
        return self._id_counter

    async def start(self) -> None:
        """Launch Burp subprocess, initialize, and discover tools.
        
        Raises:
            RuntimeError: If subprocess fails to start or initialization fails.
        """
        log.info("Launching Burp MCP subprocess: %s", self.cmd)
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *shlex.split(self.cmd),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as e:
            log.error("Failed to launch Burp: command not found - %s", e)
            raise RuntimeError(f"Burp command not found: {self.cmd}") from e
        except Exception as e:
            log.error("Failed to launch Burp subprocess: %s", e)
            raise RuntimeError(f"Failed to start Burp: {e}") from e
        
        asyncio.create_task(self._reader_loop())
        asyncio.create_task(self._stderr_logger())
        
        try:
            await self._initialize()
            self._tools = await self._list_tools()
            log.info("Burp MCP ready with %d tool(s)", len(self._tools))
        except asyncio.TimeoutError:
            log.error("Burp initialization timed out")
            await self.stop()
            raise RuntimeError("Burp MCP server initialization timed out") from None

    async def _stderr_logger(self) -> None:
        """Log stderr from subprocess."""
        if not self._proc or not self._proc.stderr:
            return
        try:
            while not self._proc.stderr.at_eof():
                line = await self._proc.stderr.readline()
                if line:
                    log.debug("[burp stderr] %s", line.decode(errors="replace").rstrip())
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("Error reading stderr: %s", e)

    async def _reader_loop(self) -> None:
        """Continuously read framed messages from Burp's stdout.
        
        Handles Content-Length framing and dispatches complete messages.
        """
        if not self._proc or not self._proc.stdout:
            return
        
        buf = b""
        try:
            while not self._proc.stdout.at_eof():
                chunk = await self._proc.stdout.read(READ_BUFFER_SIZE)
                if not chunk:
                    log.debug("Burp stdout EOF reached")
                    break
                
                buf += chunk
                
                # Parse all complete messages in buffer
                while b"\r\n\r\n" in buf:
                    header_part, rest = buf.split(b"\r\n\r\n", 1)
                    headers, content_length = _parse_headers(header_part)
                    
                    if content_length == 0:
                        log.warning("Received message with zero content length")
                        break
                    
                    if len(rest) < content_length:
                        break  # Wait for more data
                    
                    body = rest[:content_length]
                    buf = rest[content_length:]
                    
                    try:
                        msg = json.loads(body.decode("utf-8"))
                        log.debug("[burp ←] %s", json.dumps(msg)[:300])
                        self._dispatch(msg)
                    except json.JSONDecodeError as e:
                        log.error("Failed to parse JSON from Burp: %s", e)
                    except Exception as e:
                        log.error("Error dispatching Burp message: %s", e)
        
        except asyncio.CancelledError:
            log.debug("Reader loop cancelled")
        except Exception as e:
            log.error("Fatal error in reader loop: %s", e)

    def _dispatch(self, msg: dict) -> None:
        """Dispatch response to matching pending request.
        
        Args:
            msg: Parsed JSON-RPC response or notification.
        """
        msg_id = msg.get("id")
        if msg_id is None or msg_id not in self._pending:
            # Notifications or unsolicited messages
            log.debug("Ignoring message without matching request ID: %s", msg_id)
            return
        
        fut = self._pending.pop(msg_id)
        if fut.done():
            log.warning("Future already done for request %s", msg_id)
            return
        
        if "error" in msg:
            error = msg["error"]
            error_msg = error.get("message", "Unknown error")
            fut.set_exception(RuntimeError(f"Burp RPC error: {error_msg}"))
        else:
            fut.set_result(msg.get("result"))

    async def _send(self, method: str, params: Optional[dict] = None) -> Any:
        """Send a JSON-RPC request to Burp and wait for response.
        
        Args:
            method: JSON-RPC method name.
            params: Optional method parameters.
            
        Returns:
            The result field from the response.
            
        Raises:
            RuntimeError: If response contains an error.
            asyncio.TimeoutError: If response times out.
        """
        if not self._proc or not self._proc.stdin:
            raise RuntimeError("Burp subprocess not running")
        
        msg_id = self._next_id()
        loop = asyncio.get_event_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending[msg_id] = fut
        
        data = make_request(msg_id, method, params)
        log.debug("[burp →] %s", json.loads(data.split(b"\r\n\r\n", 1)[1]))
        
        try:
            self._proc.stdin.write(data)
            await self._proc.stdin.drain()
            return await asyncio.wait_for(fut, timeout=MCP_RPC_TIMEOUT)
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            log.error("Burp RPC timeout for method %s", method)
            raise

    async def _initialize(self) -> None:
        """Initialize connection with Burp MCP server.
        
        Raises:
            RuntimeError: If initialization fails.
        """
        try:
            result = await self._send("initialize", {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "clientInfo": {"name": "burp-mcp-proxy", "version": "1.0.0"},
            })
            log.info("Burp server initialized: %s", result)
            
            # Send initialized notification
            if self._proc and self._proc.stdin:
                notif = make_notification("notifications/initialized")
                self._proc.stdin.write(notif)
                await self._proc.stdin.drain()
            
            self._initialized = True
        except Exception as e:
            log.error("Initialization failed: %s", e)
            raise RuntimeError(f"Failed to initialize Burp: {e}") from e

    async def _list_tools(self) -> list[dict]:
        """Discover available tools from Burp.
        
        Returns:
            List of tool definitions.
        """
        try:
            result = await self._send("tools/list", {})
            tools = result.get("tools", [])
            log.debug("Discovered %d tool(s)", len(tools))
            return tools
        except Exception as e:
            log.error("Failed to list tools: %s", e)
            return []

    async def call_tool(self, name: str, arguments: dict) -> Any:
        """Call a tool in Burp.
        
        Args:
            name: Tool name.
            arguments: Tool arguments.
            
        Returns:
            Tool result.
            
        Raises:
            RuntimeError: If tool call fails.
        """
        log.debug("Calling tool: %s with args: %s", name, list(arguments.keys()))
        return await self._send("tools/call", {"name": name, "arguments": arguments})

    @property
    def tools(self) -> list[dict]:
        """Get discovered tools."""
        return self._tools

    async def stop(self) -> None:
        """Gracefully stop Burp subprocess."""
        if not self._proc:
            return
        
        log.info("Shutting down Burp subprocess")
        try:
            self._proc.terminate()
            await asyncio.wait_for(self._proc.wait(), timeout=5)
            log.info("Burp subprocess terminated gracefully")
        except asyncio.TimeoutError:
            log.warning("Burp subprocess did not terminate, killing forcefully")
            self._proc.kill()
            await self._proc.wait()
        except Exception as e:
            log.error("Error stopping Burp subprocess: %s", e)


# ---- Proxy MCP server (exposed to Claude via stdio) ----

class BurpMCPProxy:
    """MCP server that proxies tool calls to Burp.
    
    Implements the Model Context Protocol (MCP) server interface,
    reading requests from Claude (stdin), forwarding tool calls to Burp,
    and writing responses back (stdout).
    """

    def __init__(self, burp: BurpMCPClient):
        """Initialize proxy with Burp client.
        
        Args:
            burp: BurpMCPClient instance.
        """
        self.burp = burp
        self._initialized = False
        self._shutdown = False

    async def run(self) -> None:
        """Main event loop: read from Claude, dispatch to Burp, write responses.
        
        Raises:
            RuntimeError: On fatal I/O errors.
        """
        try:
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            loop = asyncio.get_event_loop()
            
            try:
                await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
            except NotImplementedError:
                log.warning("stdin pipe not supported on this platform, using reader directly")
                reader = asyncio.StreamReader()
            
            await loop.connect_write_pipe(asyncio.BaseProtocol, sys.stdout.buffer)

            log.info("Proxy stdio loop started")
            buf = b""
            
            while not self._shutdown:
                chunk = await reader.read(READ_BUFFER_SIZE)
                if not chunk:
                    log.info("Claude closed stdin, shutting down")
                    break
                
                buf += chunk
                
                # Parse all complete messages in buffer
                while b"\r\n\r\n" in buf:
                    header_part, rest = buf.split(b"\r\n\r\n", 1)
                    headers, content_length = _parse_headers(header_part)
                    
                    if content_length == 0:
                        log.warning("Received message with zero content length")
                        break
                    
                    if len(rest) < content_length:
                        break  # Wait for more data
                    
                    body = rest[:content_length]
                    buf = rest[content_length:]
                    
                    try:
                        msg = json.loads(body.decode("utf-8"))
                        log.debug("[claude →] %s", json.dumps(msg)[:300])
                        response = await self._handle(msg)
                        if response:
                            log.debug("[claude ←] %s", response[:300])
                            sys.stdout.buffer.write(response)
                            sys.stdout.buffer.flush()
                    except json.JSONDecodeError as e:
                        log.error("Failed to parse JSON from Claude: %s", e)
                    except Exception as e:
                        log.error("Error handling Claude message: %s", e, exc_info=True)
        
        except Exception as e:
            log.error("Fatal error in proxy loop: %s", e, exc_info=True)
            self._shutdown = True

    async def _handle(self, msg: dict) -> Optional[bytes]:
        """Handle a message from Claude.
        
        Args:
            msg: Parsed JSON-RPC request message.
            
        Returns:
            Response bytes to write to stdout, or None for notifications.
        """
        method = msg.get("method", "")
        msg_id = msg.get("id")
        params = msg.get("params", {})

        # Notifications have no id — fire and forget
        if msg_id is None:
            log.debug("Received notification: %s", method)
            return None

        try:
            if method == "initialize":
                self._initialized = True
                return make_response(msg_id, {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "burp-mcp-proxy", "version": "1.0.0"},
                })

            elif method == "tools/list":
                tools = self.burp.tools
                log.debug("Returning %d tool(s) to Claude", len(tools))
                return make_response(msg_id, {"tools": tools})

            elif method == "tools/call":
                name = params.get("name")
                arguments = params.get("arguments", {})
                
                if not name:
                    return make_error(msg_id, -32602, "Missing tool name")
                
                log.info("Forwarding tool call: %s", name)
                result = await self.burp.call_tool(name, arguments)
                return make_response(msg_id, result)

            elif method == "ping":
                return make_response(msg_id, {})

            else:
                log.warning("Unknown method: %s", method)
                return make_error(msg_id, -32601, f"Method not found: {method}")

        except asyncio.TimeoutError:
            log.error("Tool call timed out")
            return make_error(msg_id, -32000, "Burp MCP server timed out")
        except Exception as exc:
            log.error("Error handling %s: %s", method, exc, exc_info=True)
            # Don't leak internal errors to Claude
            return make_error(msg_id, -32000, "Internal server error")


# ---- Entry point ----

async def main() -> int:
    """Main entry point.
    
    Returns:
        Exit code (0 for success, 1 for failure).
    """
    parser = argparse.ArgumentParser(
        description="Burp Suite MCP Proxy - Exposes Burp tools via Model Context Protocol",
        epilog="Set BURP_MCP_CMD environment variable to override --burp-cmd"
    )
    parser.add_argument(
        "--burp-cmd",
        default=os.environ.get("BURP_MCP_CMD", DEFAULT_BURP_CMD),
        help="Command to launch the Burp MCP server",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        help="Path to log file",
    )
    args = parser.parse_args()

    burp = BurpMCPClient(args.burp_cmd)
    
    try:
        await burp.start()
    except Exception as exc:
        log.critical("Failed to start Burp MCP server: %s", exc, exc_info=True)
        return 1

    proxy = BurpMCPProxy(burp)
    exit_code = 0
    
    try:
        await proxy.run()
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as exc:
        log.critical("Fatal error: %s", exc, exc_info=True)
        exit_code = 1
    finally:
        await burp.stop()
        log.info("Proxy shutting down")
    
    return exit_code


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
