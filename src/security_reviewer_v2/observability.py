"""Safe LangSmith observability helpers for model usage.

Only numeric token usage and provider/model identifiers are sent. Prompts,
responses, source excerpts, findings, and credentials remain outside the
trace payload.
"""

from __future__ import annotations

from typing import Any


def record_model_usage(
    *, provider: str, model: str, usage: dict[str, Any]
) -> dict[str, int] | None:
    """Attach a sanitized LLM child run to the current LangGraph run.

    LangSmith is optional for local execution, so tracing failures are ignored
    and never affect a security scan. The returned canonical usage is also
    useful to the local report pipeline.
    """
    canonical = canonical_usage(usage)
    if canonical is None:
        return None
    try:
        from langsmith.run_helpers import get_current_run_tree

        parent = get_current_run_tree()
        if parent is None:
            return canonical
        child = parent.create_child(
            name=f"{provider}:{model}",
            run_type="llm",
            inputs={},
            serialized={"name": model, "provider": provider},
            tags=["verdict", "model-usage"],
        )
        safe_metadata = {
            "provider": provider,
            "model": model,
            "usage_metadata": canonical,
        }
        child.end(
            outputs={"usage_metadata": canonical},
            metadata=safe_metadata,
        )
        child.post()
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        # Observability must never change scanner or agent behavior.
        pass
    return canonical


def canonical_usage(usage: dict[str, Any]) -> dict[str, int] | None:
    """Normalize Groq/OpenAI/Ollama usage names to LangSmith conventions."""
    prompt = _as_nonnegative_int(
        usage.get("prompt_tokens", usage.get("prompt_eval_count"))
    )
    completion = _as_nonnegative_int(
        usage.get("completion_tokens", usage.get("eval_count"))
    )
    total = _as_nonnegative_int(usage.get("total_tokens"))
    if total is None and prompt is not None and completion is not None:
        total = prompt + completion
    if prompt is None and completion is None and total is None:
        return None
    result: dict[str, int] = {}
    if prompt is not None:
        result["input_tokens"] = prompt
        result["prompt_tokens"] = prompt
    if completion is not None:
        result["output_tokens"] = completion
        result["completion_tokens"] = completion
    if total is not None:
        result["total_tokens"] = total
    return result


def _as_nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None
