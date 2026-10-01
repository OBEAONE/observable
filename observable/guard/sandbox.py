"""
Block 5b — tool execution sandbox (§9.10).

The last row left in ARCHITECTURE.md §5 marked "intentionally left for
v2": sandboxed execution. Every other gap closed so far in this series
(§9.7 resource scoping, §9.8 JIT elevation, §9.9 rate limiting) bounds
*whether* a call is authorized. This bounds something different: once a
call *is* authorized, what the tool invoker itself is allowed to do to
the Gateway process while it runs — specifically, how long it may run
and how large a result it may hand back — independent of whether the
tool's own code is slow, buggy, hung, or (if a tool were ever
compromised) deliberately trying to exhaust the service it's running
in.

**Honest about what this is.** Observable's tools are first-party
Python callables registered in-process by whoever deploys it
(``AgentGuard.register_tool``), not arbitrary untrusted code uploaded by
an end user — so the threat model here is "a buggy or runaway tool
degrades the service for other agents," not "a malicious tool escapes
to the host." Real OS-level isolation (a separate process, a container,
a seccomp/gVisor sandbox, a network-egress boundary) would be needed for
that threat model, and would also require tools to be invoked across a
process boundary rather than as plain in-process closures — a
rearchitecture out of scope here (see ARCHITECTURE.md §9.10, "What
v1.10 does *not* do"). What's built here is the bounded, honestly-scoped
piece: a wall-clock execution deadline and a cap on result size, enforced
without assuming anything about what's inside the tool.

**Daemon worker thread, not a shared pool.** Each sandboxed call runs on
its own ``threading.Thread(daemon=True)``. Deliberately not a
pooled/non-daemon executor: a daemon thread is abandoned by the
interpreter at process exit rather than blocking it, so a tool that
genuinely never returns can't also wedge a graceful shutdown. Python
gives no safe, portable way to forcibly kill a running thread, so a
timed-out invocation's thread is *not* killed — it keeps running in the
background, still consuming CPU until it finishes or the process exits.
What the timeout actually buys is bounding how long the *caller*
(Gateway's ``invoke()``, and whatever's waiting on it — an HTTP request
worker) is blocked on a single call: it is released the instant the
deadline passes, free to serve the next request, rather than hanging
indefinitely on one bad tool.
"""
from __future__ import annotations

import json
import threading
from typing import Callable, Optional

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_RESULT_BYTES = 1_000_000  # 1 MB


class SandboxViolation(Exception):
    """Raised when the sandbox boundary itself stops an invocation —
    not the tool's own code raising. Kept as its own exception type
    (rather than reusing the tool's exception path) so Gateway and the
    audit trail can say *why execution was stopped*, in the sandbox's
    own words, distinct from whatever exception text a tool itself
    might have produced."""


class ToolTimeoutError(SandboxViolation):
    """The invoker did not return within the configured wall-clock
    deadline."""


class ResultTooLargeError(SandboxViolation):
    """The invoker returned, but its JSON-encoded result exceeds the
    configured size cap."""


def run_sandboxed(
    invoker: Callable[[dict, Optional[str]], dict],
    payload: dict,
    resource_id: Optional[str],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
) -> dict:
    """Execute ``invoker(payload, resource_id)`` under the sandbox's two
    bounds. Returns the invoker's result unchanged on success. Raises
    ``ToolTimeoutError`` if it doesn't return within ``timeout_seconds``,
    ``ResultTooLargeError`` if its encoded result exceeds
    ``max_result_bytes``, or re-raises whatever exception the invoker
    itself raised (same object, same traceback) so an existing caller's
    handling of a tool's own errors is completely unaffected by this
    wrapper being added."""
    outcome: dict = {}
    done = threading.Event()

    def _run() -> None:
        try:
            outcome["result"] = invoker(payload, resource_id)
        except Exception as exc:  # noqa: BLE001 - tool code is untrusted; re-raised as-is below
            outcome["exception"] = exc
        finally:
            done.set()

    worker = threading.Thread(target=_run, daemon=True, name="observable-tool-sandbox")
    worker.start()
    finished = done.wait(timeout=timeout_seconds)
    if not finished:
        raise ToolTimeoutError(
            f"tool execution did not return within the {timeout_seconds:.1f}s sandbox timeout"
        )

    if "exception" in outcome:
        raise outcome["exception"]

    result = outcome["result"]
    try:
        encoded_size = len(json.dumps(result).encode("utf-8"))
    except (TypeError, ValueError):
        # Not JSON-serializable -- not this boundary's concern to
        # diagnose; Gateway's own output-encoding path downstream
        # reports that failure in its own terms.
        return result
    if encoded_size > max_result_bytes:
        raise ResultTooLargeError(
            f"tool result is {encoded_size} bytes, exceeding the "
            f"{max_result_bytes}-byte sandbox result cap"
        )
    return result
