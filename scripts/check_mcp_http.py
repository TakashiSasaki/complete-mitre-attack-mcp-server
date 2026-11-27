"""Check the loopback HTTP server and its local Caddy HTTPS route."""

import argparse
import asyncio
import json
from time import perf_counter

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client


class CaddyLoopbackTransport(httpx.AsyncHTTPTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # Keep the original Host and verify the TLS certificate for that name.
        request.extensions["sni_hostname"] = request.url.host
        request.url = request.url.copy_with(host="127.0.0.1")
        return await super().handle_async_request(request)


class ProbeError(Exception):
    pass


def error_label(exc: Exception) -> str:
    if isinstance(exc, ExceptionGroup):
        return ",".join(error_label(error) for error in exc.exceptions)
    if isinstance(exc, httpx.HTTPStatusError):
        return f"http_{exc.response.status_code}"
    if isinstance(exc, ProbeError):
        return str(exc)
    return type(exc).__name__


async def check_once(origin, server_name, expected_tool, via_caddy):
    transport = CaddyLoopbackTransport() if via_caddy else None
    async with asyncio.timeout(18), httpx.AsyncClient(
        transport=transport, trust_env=False, timeout=httpx.Timeout(18, connect=3),
        headers={"User-Agent": "mcp-readiness/1"},
    ) as client:
        health = await client.get(f"{origin}/healthz")
        health.raise_for_status()
        status = health.json()
        if status.get("status") != "ok" or status.get("service") != server_name:
            raise ProbeError("healthz_service_or_status")

        async with streamable_http_client(f"{origin}/mcp", http_client=client) as (read, write, _):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                if initialized.serverInfo.name != server_name:
                    raise ProbeError("initialize_server_name")
                listing = await session.list_tools()
                if expected_tool not in {tool.name for tool in listing.tools}:
                    raise ProbeError("tools_list_missing_expected_tool")
                return len(listing.tools)


async def probe(origin, server_name, expected_tool, via_caddy=False):
    started = perf_counter()
    record = {
        "service": server_name,
        "route": "caddy" if via_caddy else "loopback",
        "check": "healthz_initialize_tools_list",
    }
    try:
        record["tools"] = await check_once(origin, server_name, expected_tool, via_caddy)
        record["status"] = "ok"
    except Exception as exc:
        record["status"] = "failed"
        record["error"] = error_label(exc)
    record["duration_ms"] = round((perf_counter() - started) * 1000, 2)
    print(json.dumps(record))
    return record["status"] == "ok"


async def run(args):
    checks = [probe(f"http://127.0.0.1:{args.port}", args.server, args.tool)]
    if args.caddy_host:
        checks.append(probe(f"https://{args.caddy_host}", args.server, args.tool, via_caddy=True))
    return all(await asyncio.gather(*checks))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int)
    parser.add_argument("server", help="Expected server name")
    parser.add_argument("tool", help="Expected name in tools/list")
    parser.add_argument("--caddy-host", help="HTTPS virtual host on the local Caddy listener")
    raise SystemExit(0 if asyncio.run(run(parser.parse_args())) else 1)


if __name__ == "__main__":
    main()
