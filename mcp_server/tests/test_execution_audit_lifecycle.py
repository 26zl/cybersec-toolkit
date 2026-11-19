"""Audit lifecycle coverage for calls rejected or cancelled before a child runs."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

from mcp_server import security


@pytest.mark.parametrize("failure", ["policy", "rate", "cancelled"])
async def test_pipeline_start_always_gets_result(failure, tools_db, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _binary: "/synthetic/bin/tool")
    limiter = security._RateLimiter(max_per_minute=0 if failure == "rate" else 1000)
    monkeypatch.setattr(security, "_rate_limiter", limiter)
    start = Mock(return_value="synthetic-pipeline")
    result = Mock()
    monkeypatch.setattr(security, "log_pipeline_start", start)
    monkeypatch.setattr(security, "log_pipeline_result", result)
    if failure == "policy":
        monkeypatch.setattr(security, "check_policy", Mock(side_effect=ValueError("synthetic rejection")))
    elif failure == "cancelled":
        monkeypatch.setattr(security.asyncio, "to_thread", AsyncMock(side_effect=asyncio.CancelledError))

    with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn:
        if failure == "cancelled":
            with pytest.raises(asyncio.CancelledError):
                await security.execute_pipeline([{"tool": "cat"}], tools_db)
        else:
            response = await security.execute_pipeline([{"tool": "cat"}], tools_db)
            assert response["exit_code"] == -1
        spawn.assert_not_called()

    start.assert_called_once()
    result.assert_called_once()
    assert result.call_args.args[0] == "synthetic-pipeline"
    assert result.call_args.kwargs["outcome"] == ("cancelled" if failure == "cancelled" else "error")


async def test_script_queued_cancellation_does_not_log_execution(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_SCRIPTS", "1")
    limiter = security._RateLimiter(max_concurrent=1, max_per_minute=1000)
    monkeypatch.setattr(security, "_rate_limiter", limiter)
    waiting = asyncio.Event()

    class WaitingSemaphore:
        async def __aenter__(self):
            waiting.set()
            await asyncio.Future()

        async def __aexit__(self, *_args):
            pass

    limiter._semaphore = WaitingSemaphore()
    with (
        patch.object(security, "log_script_execution") as start,
        patch.object(security, "log_script_result") as result,
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock) as spawn,
    ):
        task = asyncio.create_task(security.execute_script("pass"))
        await asyncio.wait_for(waiting.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        start.assert_not_called()
        result.assert_not_called()
        spawn.assert_not_called()


async def test_script_cancelled_during_spawn_has_a_result(monkeypatch):
    monkeypatch.setenv("CYBERSEC_MCP_ALLOW_SCRIPTS", "1")
    monkeypatch.setattr(security, "_rate_limiter", security._RateLimiter(max_per_minute=1000))
    monkeypatch.setattr(security, "_sandbox_wrap", lambda command, **_kwargs: command)
    with (
        patch.object(security, "log_script_execution") as start,
        patch.object(security, "log_script_result") as result,
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, side_effect=asyncio.CancelledError),
    ):
        with pytest.raises(asyncio.CancelledError):
            await security.execute_script("pass")
        start.assert_called_once()
        result.assert_called_once()
        assert result.call_args.kwargs["outcome"] == "cancelled"


async def test_tool_cancelled_during_spawn_has_an_execution_record(tools_db, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _binary: "/synthetic/bin/tool")
    monkeypatch.setattr(security, "_rate_limiter", security._RateLimiter(max_per_minute=1000))
    monkeypatch.setattr(security, "_sandbox_wrap", lambda command, **_kwargs: command)
    with (
        patch.object(security, "log_execution") as result,
        patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, side_effect=asyncio.CancelledError),
    ):
        with pytest.raises(asyncio.CancelledError):
            await security.execute_tool("cat", "", tools_db)
        result.assert_called_once()
        assert result.call_args.kwargs["outcome"] == "cancelled"
