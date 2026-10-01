import time

import pytest

from observable.guard.sandbox import (
    ResultTooLargeError,
    ToolTimeoutError,
    run_sandboxed,
)


def test_fast_invoker_returns_result_unchanged():
    def tool(payload, resource_id):
        return {"ok": True, "resource_id": resource_id, "echo": payload}

    result = run_sandboxed(tool, {"a": 1}, "R-1", timeout_seconds=1.0, max_result_bytes=1000)
    assert result == {"ok": True, "resource_id": "R-1", "echo": {"a": 1}}


def test_invoker_exception_is_reraised_unchanged():
    class CustomError(RuntimeError):
        pass

    def tool(payload, resource_id):
        raise CustomError("downstream API timed out")

    with pytest.raises(CustomError, match="downstream API timed out"):
        run_sandboxed(tool, {}, None, timeout_seconds=1.0, max_result_bytes=1000)


def test_timeout_raises_when_invoker_runs_past_the_deadline():
    def tool(payload, resource_id):
        time.sleep(0.3)
        return {"ok": True}

    with pytest.raises(ToolTimeoutError, match="0.1s sandbox timeout"):
        run_sandboxed(tool, {}, None, timeout_seconds=0.1, max_result_bytes=1000)


def test_caller_is_released_promptly_even_though_the_thread_keeps_running():
    # The hung tool's own thread is abandoned (daemon=True, not killed)
    # but run_sandboxed() itself must return control well before the
    # tool actually finishes -- that's the whole point of the timeout.
    def tool(payload, resource_id):
        time.sleep(0.4)
        return {"ok": True}

    started = time.monotonic()
    with pytest.raises(ToolTimeoutError):
        run_sandboxed(tool, {}, None, timeout_seconds=0.05, max_result_bytes=1000)
    elapsed = time.monotonic() - started
    assert elapsed < 0.4


def test_oversized_result_raises_result_too_large():
    def tool(payload, resource_id):
        return {"blob": "x" * 1000}

    with pytest.raises(ResultTooLargeError, match="exceeding the 100-byte"):
        run_sandboxed(tool, {}, None, timeout_seconds=1.0, max_result_bytes=100)


def test_result_under_the_cap_is_allowed_through():
    def tool(payload, resource_id):
        return {"blob": "x" * 10}

    result = run_sandboxed(tool, {}, None, timeout_seconds=1.0, max_result_bytes=10_000)
    assert result == {"blob": "x" * 10}


def test_non_serializable_result_passes_through_unchanged():
    # Not this boundary's job to diagnose -- Gateway's own output
    # encoding path reports that failure in its own terms.
    sentinel = object()

    def tool(payload, resource_id):
        return {"obj": sentinel}

    result = run_sandboxed(tool, {}, None, timeout_seconds=1.0, max_result_bytes=1000)
    assert result == {"obj": sentinel}


def test_default_bounds_are_generous_enough_for_a_normal_call():
    def tool(payload, resource_id):
        return {"ok": True}

    # No explicit timeout_seconds/max_result_bytes -- the module's own
    # defaults must not reject an ordinary, fast, small-result call.
    result = run_sandboxed(tool, {}, None)
    assert result == {"ok": True}
