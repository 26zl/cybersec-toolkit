#!/usr/bin/env python3
"""Check that a model behind an OpenAI-compatible endpoint can call this server's MCP tools.

The MCP client picks the model, so whether a given model can drive the toolkit is a
property of that model and its runtime, not of this server. This sends the server's
real tool definitions to the endpoint, asks for one harmless tool call
(``list_profiles``), runs it, returns the result, and checks the answer uses it.

It works with any endpoint that speaks the OpenAI chat-completions format: a local
runtime (Ollama, LM Studio, llama.cpp, vLLM) or a hosted provider or gateway.

Usage (from the repository root):
    uv run --directory mcp_server python ../scripts/check_model_tools.py \\
        --base-url http://localhost:11434/v1 --model <model>

    # hosted endpoint: the key is read from the named environment variable
    uv run --directory mcp_server python ../scripts/check_model_tools.py \\
        --base-url https://api.example.com/v1 --model <model> --api-key-env MY_API_KEY

Only the tool definitions and a fixed question are sent; no target data is involved.
The server runs in-process for the check and logs to a temporary file.

Exit status: 0 the model called the tool and used its result, 1 it did not, 2 the
endpoint could not be reached or rejected the request.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
QUESTION = "Which install profiles does this toolkit offer? Use the list_profiles tool, then name two of them."
EXPECTED_TOOL = "list_profiles"


def validate_base_url(url: str) -> str | None:
    """Return a problem with the endpoint URL, or None: https, or http only to a loopback host."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname
    except ValueError:
        return "the base URL is not valid"
    if parsed.scheme == "https" and host:
        return None
    if parsed.scheme == "http" and host:
        if host == "localhost":
            return None
        try:
            if ipaddress.ip_address(host).is_loopback:
                return None
        except ValueError:
            pass
        return "plain http is only allowed to a loopback host; use https so the API key is not sent in cleartext"
    return "the base URL must be an https URL (or http to localhost)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
        return None


def chat(base_url: str, api_key: str | None, payload: dict, timeout: float) -> dict:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})},
    )
    opener = urllib.request.build_opener(_NoRedirect) if api_key else urllib.request.build_opener()
    with opener.open(request, timeout=timeout) as response:
        return json.loads(response.read())


def result_text(result: object) -> str:
    """Flatten an MCP tool result to the text a chat message can carry."""
    structured = getattr(result, "structured_content", None)
    if structured is not None:
        return json.dumps(structured)
    return "\n".join(getattr(block, "text", "") for block in getattr(result, "content", []) or [])


async def run(args: argparse.Namespace) -> int:
    # Set before the server is imported, so the check never writes to the operator's audit log.
    scratch = tempfile.TemporaryDirectory()
    os.environ["CYBERSEC_MCP_AUDIT_LOG"] = str(Path(scratch.name) / "audit.log")
    sys.path.insert(0, str(REPO_ROOT))
    from fastmcp import Client  # noqa: PLC0415

    from mcp_server.server import mcp  # noqa: PLC0415

    api_key = os.environ.get(args.api_key_env) if args.api_key_env else None
    if args.api_key_env and not api_key:
        print("error: the environment variable named by --api-key-env is not set", file=sys.stderr)
        return 2

    async with Client(mcp) as client:
        definitions = await client.list_tools()
        tools = [
            {
                "type": "function",
                "function": {"name": t.name, "description": t.description or "", "parameters": t.input_schema},
            }
            for t in definitions
        ]
        print(f"server: {len(tools)} tools, {len(json.dumps(tools)) // 1024} KiB of tool definitions")
        messages: list[dict] = [{"role": "user", "content": QUESTION}]
        payload = {"model": args.model, "messages": messages, "tools": tools, "temperature": 0}

        try:
            started = time.monotonic()
            first = chat(args.base_url, api_key, payload, args.timeout)
        except urllib.error.HTTPError as exc:
            detail = exc.read(600).decode(errors="replace").strip()
            print(f"FAIL: the endpoint rejected a request with tool definitions (HTTP {exc.code}): {detail}")
            return 2
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"error: could not reach {args.base_url}: {exc}", file=sys.stderr)
            return 2

        prompt_tokens = (first.get("usage") or {}).get("prompt_tokens", "not reported")
        print(f"first reply: {time.monotonic() - started:.0f}s, prompt tokens: {prompt_tokens}")
        message = (first.get("choices") or [{}])[0].get("message") or {}
        calls = message.get("tool_calls") or []
        if not calls:
            print("FAIL: the model answered without calling a tool")
            print(f"  it said: {str(message.get('content'))[:200]!r}")
            return 1

        call = calls[0].get("function") or {}
        known = {t.name for t in definitions}
        if call.get("name") not in known:
            print(f"FAIL: the model called a tool the server does not have: {call.get('name')!r}")
            return 1
        try:
            arguments = json.loads(call.get("arguments") or "{}")
        except json.JSONDecodeError:
            print(f"FAIL: the tool call arguments are not valid JSON: {str(call.get('arguments'))[:200]!r}")
            return 1
        print(f"tool call: {call['name']}({json.dumps(arguments)})")
        if call["name"] != EXPECTED_TOOL:
            print(f"FAIL: expected a call to {EXPECTED_TOOL}")
            return 1

        outcome = result_text(await client.call_tool(call["name"], arguments))
        profiles = (
            [p.get("name", "") for p in json.loads(outcome).get("profiles", [])] if outcome.startswith("{") else []
        )
        messages.append({"role": "assistant", "content": message.get("content") or "", "tool_calls": calls})
        messages.append({"role": "tool", "tool_call_id": calls[0].get("id", "call_0"), "content": outcome})
        try:
            second = chat(args.base_url, api_key, {**payload, "messages": messages}, args.timeout)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"FAIL: the request carrying the tool result failed: {exc}")
            return 1
        answer = ((second.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        named = [name for name in profiles if name and name in answer.lower()]
        if len(named) < 2:
            print(f"FAIL: the answer does not use the tool result: {answer[:200]!r}")
            return 1
        print(f"PASS: the model called {EXPECTED_TOOL} and answered from its result ({', '.join(named[:4])})")
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True, help="OpenAI-compatible base URL, ending in /v1")
    parser.add_argument("--model", required=True, help="model name as the endpoint knows it")
    parser.add_argument("--api-key-env", metavar="VAR", help="environment variable that holds the API key")
    parser.add_argument("--timeout", type=float, default=600, help="seconds to wait for each reply")
    args = parser.parse_args(argv)
    problem = validate_base_url(args.base_url)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
