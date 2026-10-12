"""One wall-clock and network/output budget shared by a chat turn's providers."""

from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from app.core.errors import UpstreamServiceError


class ModelBudgetExceededError(UpstreamServiceError):
    code = "model_budget_exhausted"
    message = "The model request budget is exhausted."


@dataclasses.dataclass
class ModelBudget:
    deadline: float
    max_calls: int
    max_output_tokens: int
    network_calls: int = 0
    allocated_output_tokens: int = 0
    failures: int = 0
    exhausted: bool = False
    network_elapsed_ms: float = 0
    reported_prompt_tokens: int | None = None
    reported_completion_tokens: int | None = None

    def reserve(self, output_tokens: int) -> float:
        remaining = self.deadline - time.monotonic()
        if (
            remaining <= 0
            or self.network_calls >= self.max_calls
            or self.allocated_output_tokens + output_tokens > self.max_output_tokens
        ):
            self.exhausted = True
            raise ModelBudgetExceededError()
        self.network_calls += 1
        self.allocated_output_tokens += output_tokens
        return remaining

    def record_usage(self, usage: Any) -> None:
        if not isinstance(usage, dict):
            return
        for key, attribute in (
            ("prompt_tokens", "reported_prompt_tokens"),
            ("completion_tokens", "reported_completion_tokens"),
        ):
            value = usage.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                setattr(self, attribute, (getattr(self, attribute) or 0) + value)

    def metadata(self) -> dict[str, Any]:
        return {
            "network_calls": self.network_calls,
            "allocated_output_tokens": self.allocated_output_tokens,
            "failures": self.failures,
            "budget_exhausted": self.exhausted,
            "network_elapsed_ms": round(self.network_elapsed_ms, 2),
            "reported_prompt_tokens": self.reported_prompt_tokens,
            "reported_completion_tokens": self.reported_completion_tokens,
        }


CURRENT_BUDGET: contextvars.ContextVar[ModelBudget | None] = contextvars.ContextVar(
    "model_budget", default=None
)


@contextmanager
def model_budget(seconds: float, max_calls: int, max_output_tokens: int) -> Iterator[ModelBudget]:
    budget = ModelBudget(time.monotonic() + seconds, max_calls, max_output_tokens)
    token = CURRENT_BUDGET.set(budget)
    try:
        yield budget
    finally:
        CURRENT_BUDGET.reset(token)


def provider_post(
    url: str,
    *,
    json: dict[str, Any],
    headers: dict[str, str],
    timeout: float,
    output_tokens: int = 0,
):
    """In chat, async cancellation bounds headers AND the complete response body.

    The synchronous provider interface runs in FastAPI's worker thread. Outside
    chat, the existing synchronous transport remains available for startup/tools.
    """
    import httpx

    budget = CURRENT_BUDGET.get()
    if budget is None:
        return httpx.post(url, json=json, headers=headers, timeout=timeout)
    remaining = budget.reserve(output_tokens)
    started = time.monotonic()

    async def request():
        async with asyncio.timeout(max(0, budget.deadline - time.monotonic())):
            async with httpx.AsyncClient(timeout=min(timeout, remaining)) as client:
                return await client.post(url, json=json, headers=headers)

    try:
        response = asyncio.run(request())
        response.raise_for_status()
        body = response.json()
        budget.record_usage(body.get("usage") if isinstance(body, dict) else None)
        return response
    except TimeoutError as exc:
        budget.exhausted = True
        budget.failures += 1
        raise ModelBudgetExceededError() from exc
    except Exception:
        budget.failures += 1
        raise
    finally:
        budget.network_elapsed_ms += (time.monotonic() - started) * 1000
