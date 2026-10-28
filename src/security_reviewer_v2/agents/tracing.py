"""LangSmith tracing for the LangGraph agents: opt-in, redacted, zero-cost when disabled.

Enable (standard LangSmith variables)::

    export LANGSMITH_TRACING=true
    export LANGSMITH_API_KEY=...            # https://smith.langchain.com
    export LANGSMITH_PROJECT=security-reviewer-v2   # optional (this is the default)

Privacy.  Prompts contain repository source code, so *what* leaves the machine is controlled by
``SECURITY_REVIEWER_TRACE_CONTENT``:

``metadata`` (default)
    Graph structure, node names, timings, counts, statuses and token usage.  Every long string
    (prompts, code, model output) is replaced by ``<hidden N chars sha256:…>``.
``redacted``
    Prompts and outputs are sent after ``redact_source`` removed credentials and each string is
    truncated to 4,000 characters.
``full``
    Like ``redacted`` without truncation.  Use only for non-sensitive targets.

The scrubbing is attached to the LangSmith ``Client`` used by these agents, so it applies to graph
nodes and model calls alike, even if ``LANGSMITH_TRACING`` is set globally.
"""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, nullcontext
from functools import lru_cache
from typing import Any

from langsmith import Client, trace, traceable, tracing_context
from langsmith.run_helpers import get_current_run_tree, get_tracing_context

from security_reviewer_v2.redaction import redact_source

log = logging.getLogger(__name__)

DEFAULT_PROJECT = "security-reviewer-v2"
CONTENT_ENV = "SECURITY_REVIEWER_TRACE_CONTENT"
_VISIBLE_CHARS = 200          # strings up to this length are metadata (ids, statuses, titles)
_TRUNCATE_CHARS = 4_000       # "redacted" mode limit per string
_MODES = ("metadata", "redacted", "full")

JsonScrubber = Callable[[Any], Any]


def content_mode() -> str:
    mode = os.environ.get(CONTENT_ENV, "metadata").strip().lower()
    return mode if mode in _MODES else "metadata"


def make_scrubber(mode: str | None = None) -> JsonScrubber:
    """Return a recursive scrubber implementing the privacy mode (see module docstring)."""
    selected = mode or content_mode()

    def scrub_text(text: str) -> str:
        if selected == "metadata":
            if len(text) <= _VISIBLE_CHARS:
                return redact_source(text)
            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]
            return f"<hidden {len(text)} chars sha256:{digest}>"
        cleaned = redact_source(text)
        if selected == "redacted" and len(cleaned) > _TRUNCATE_CHARS:
            return cleaned[:_TRUNCATE_CHARS] + f"…[+{len(cleaned) - _TRUNCATE_CHARS} chars truncated]"
        return cleaned

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            return scrub_text(value)
        if isinstance(value, Mapping):
            return {str(key): scrub(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set, frozenset)):
            return [scrub(item) for item in value]
        if hasattr(value, "__dataclass_fields__") and not isinstance(value, type):
            return {name: scrub(getattr(value, name)) for name in value.__dataclass_fields__}
        return value

    return scrub


_TRUE = {"1", "true", "yes", "on"}
_SWITCHES = ("LANGSMITH_TRACING", "LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING")


def tracing_requested() -> bool:
    """True when a standard LangSmith switch is on and an API key is configured.

    Read from the environment on every call: ``langsmith.utils.tracing_is_enabled`` caches its
    first answer, which would hide later changes and make behaviour order-dependent.
    """
    switched_on = any(os.environ.get(name, "").strip().lower() in _TRUE for name in _SWITCHES)
    has_key = bool(os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGCHAIN_API_KEY"))
    return switched_on and has_key


def tracing_status() -> str:
    """One human-readable line saying whether traces will reach LangSmith, and why not (never silent)."""
    switched_on = any(os.environ.get(name, "").strip().lower() in _TRUE for name in _SWITCHES)
    has_key = bool(os.environ.get("LANGSMITH_API_KEY") or os.environ.get("LANGCHAIN_API_KEY"))
    if switched_on and has_key:
        project = os.environ.get("LANGSMITH_PROJECT") or os.environ.get("LANGCHAIN_PROJECT") or DEFAULT_PROJECT
        return f"LangSmith tracing: ON (project '{project}', content={content_mode()})"
    missing = [name for name, ok in (("LANGSMITH_TRACING=true", switched_on), ("LANGSMITH_API_KEY", has_key)) if not ok]
    return ("LangSmith tracing: OFF - missing " + " and ".join(missing) + ". Variables exported in PowerShell are not "
            "visible inside WSL/Linux; put them in a git-ignored .env file in the repository root.")


@lru_cache(maxsize=4)
def _client(mode: str) -> Client:
    scrub = make_scrubber(mode)
    return Client(hide_inputs=scrub, hide_outputs=scrub)


def build_client(mode: str | None = None) -> Client:
    """LangSmith client with privacy scrubbing applied to every input and output."""
    return _client(mode or content_mode())


@contextmanager
def agent_tracing(agent: str, *, metadata: Mapping[str, Any] | None = None,
                  client: Client | None = None) -> Iterator[None]:
    """Run a block under a scrubbed LangSmith client when tracing is on; otherwise do nothing.

    An already-active tracing context (for example the pipeline's) is respected, so the agent runs
    nest under it instead of starting a second, unrelated trace.
    """
    active = get_tracing_context()
    if (client is None and not tracing_requested()) or (active.get("enabled") and active.get("client") is not None):
        with nullcontext():
            yield
        return
    project = os.environ.get("LANGSMITH_PROJECT") or os.environ.get("LANGCHAIN_PROJECT") or DEFAULT_PROJECT
    try:
        resolved = client or build_client()
    except Exception:  # tracing is optional: a broken LangSmith setup must never stop a security review
        log.warning("LangSmith tracing disabled: could not create the client", exc_info=True)
        with nullcontext():
            yield
        return
    with tracing_context(enabled=True, client=resolved, project_name=project,
                         tags=["security-reviewer-v2", agent], metadata={"agent": agent, **dict(metadata or {})}):
        yield


def flush_traces(client: Client | None = None) -> None:
    """Send queued spans now. A short-lived CLI process can exit before LangSmith's background thread uploads."""
    try:
        (client or _client(content_mode())).flush()
    except Exception:  # tracing is best-effort and must never affect a security review
        log.debug("LangSmith flush failed", exc_info=True)


@contextmanager
def pipeline_trace(name: str, *, metadata: Mapping[str, Any] | None = None,
                   client: Client | None = None) -> Iterator[None]:
    """Parent span that groups every agent run of one pipeline execution into a single trace."""
    try:
        with agent_tracing(name, metadata=metadata, client=client):
            if client is None and not tracing_requested() and not get_tracing_context().get("enabled"):
                yield
                return
            with trace(name=name, run_type="chain", metadata=dict(metadata or {})):
                yield
    finally:
        if client is not None or tracing_requested():
            flush_traces(client)


def graph_config(agent: str, *, recursion_limit: int, metadata: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Runnable config for ``graph.invoke``: readable run name, tags and a sufficient step budget."""
    return {"run_name": agent, "tags": ["security-reviewer-v2", agent], "recursion_limit": recursion_limit,
            "metadata": {"agent": agent, **dict(metadata or {})}}


# ----------------------------------------------------------------------------- model-call spans
_USAGE_ALIASES = {
    "input_tokens": ("input_tokens", "prompt_tokens", "prompt_eval_count"),
    "output_tokens": ("output_tokens", "completion_tokens", "eval_count"),
    "total_tokens": ("total_tokens",),
}


def usage_metadata(usage: Any) -> dict[str, int]:
    """Map provider-specific usage keys to LangSmith's ``usage_metadata`` (cost/tokens panel)."""
    if not isinstance(usage, Mapping):
        return {}
    result: dict[str, int] = {}
    for target, names in _USAGE_ALIASES.items():
        for name in names:
            value = usage.get(name)
            if type(value) is int:
                result[target] = value
                break
    if "total_tokens" not in result and {"input_tokens", "output_tokens"} <= result.keys():
        result["total_tokens"] = result["input_tokens"] + result["output_tokens"]
    return result


def _trace_outputs(result: Any) -> dict[str, Any]:
    """LangSmith calls this with ``None`` when the traced function raised; that must not be an error."""
    if isinstance(result, tuple) and len(result) == 2:
        return {"response": result[0], "usage": result[1]}
    return {}


def call_model(provider: Any, method: str, prompt: str, *, span: str, **kwargs: Any) -> tuple[Any, Any]:
    """Invoke ``provider.<method>(prompt, **kwargs)`` inside an ``llm`` span carrying token usage.

    Tracing is strictly best-effort and can never change the outcome of the model call:

    * a provider exception propagates unchanged, even if the tracing machinery raises afterwards;
    * a successful response is returned even if the tracing machinery fails afterwards;
    * if tracing fails before the provider ran, the provider is called once, untraced.
    """
    outcome: dict[str, Any] = {}

    def invoke() -> tuple[Any, Any]:
        try:
            raw, usage = getattr(provider, method)(prompt, **kwargs)
        except BaseException as error:
            outcome["error"] = error
            raise
        outcome["result"] = (raw, usage)
        try:
            run = get_current_run_tree()
            if run is not None:
                run.metadata["usage_metadata"] = usage_metadata(usage)
                run.metadata.setdefault("ls_provider", getattr(provider, "name", "unknown"))
                run.metadata.setdefault("ls_model_name", getattr(provider, "model", "unknown"))
        except Exception:
            log.debug("could not attach usage metadata to the trace", exc_info=True)
        return raw, usage

    try:
        traced = traceable(
            name=span, run_type="llm",
            process_inputs=lambda _: {"messages": [{"role": "user", "content": prompt}], "options": _plain(kwargs)},
            process_outputs=_trace_outputs,
        )(invoke)
        return traced()
    except Exception:
        if "error" in outcome:
            raise outcome["error"]
        if "result" in outcome:
            log.warning("LangSmith tracing failed after the model call succeeded; the response is unaffected", exc_info=True)
            return outcome["result"]
        log.warning("LangSmith tracing failed before the model call; calling the model untraced", exc_info=True)
        return getattr(provider, method)(prompt, **kwargs)


def _plain(options: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in options.items() if isinstance(value, (str, int, float, bool, type(None)))}
