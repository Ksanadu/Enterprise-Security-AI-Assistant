"""Local transport/fault contracts; these are not live provider acceptance."""

import asyncio
import json
import time

import httpx
import pytest

from app.ai.llm import OpenAICompatibleLLMClient
from app.ai.model_budget import ModelBudgetExceededError, model_budget
from app.core.errors import UpstreamServiceError
from app.rag.embeddings import OpenAICompatibleEmbeddingProvider


def generator():
    return OpenAICompatibleLLMClient(
        api_key="synthetic",
        base_url="https://provider.invalid/v1",
        model="synthetic-model",
        timeout_seconds=10,
        max_retries=5,
    )


def completion(client, max_tokens=100):
    return client.complete(
        system_prompt="Synthetic policy",
        user_prompt="Synthetic question",
        context_block="Synthetic context",
        max_tokens=max_tokens,
    )


def async_transport(monkeypatch, handler):
    original = httpx.AsyncClient
    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )


def test_wall_deadline_cancels_the_complete_response_and_stops_retries(monkeypatch):
    cancelled = []

    async def stalled(request):
        try:
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise
        return httpx.Response(200, json={})

    async_transport(monkeypatch, stalled)
    started = time.monotonic()
    with model_budget(0.05, 10, 5000) as budget, pytest.raises(ModelBudgetExceededError):
        completion(generator())
    assert time.monotonic() - started < 1
    assert cancelled == [True]
    assert budget.exhausted and budget.network_calls == 1


def test_shared_call_and_token_budget_covers_retries_and_multiple_clients(monkeypatch):
    async_transport(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "choices": [{"message": {"content": "Synthetic answer"}}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 7},
            },
        ),
    )
    with model_budget(10, 1, 100) as budget:
        completion(generator())
        with pytest.raises(ModelBudgetExceededError):
            completion(generator())
    assert budget.metadata()["reported_prompt_tokens"] == 20
    assert budget.reported_completion_tokens == 7
    with model_budget(10, 10, 99) as tokens, pytest.raises(ModelBudgetExceededError):
        completion(generator())
    assert tokens.network_calls == 0


def test_model_budget_failure_keeps_high_risk_ticket_and_reports_fallback(
    client, employee_headers, app, monkeypatch
):
    from app.ai.response_generator import ResponseGenerator

    app.state.settings.chat_max_model_api_calls = 1
    app.state.chat._generator = ResponseGenerator(app.state.settings, client=generator())
    async_transport(
        monkeypatch, lambda request: httpx.Response(503, json={"error": "Synthetic outage"})
    )
    cid = client.post("/api/v1/chat/conversations", headers=employee_headers, json={}).json()["id"]
    result = client.post(
        f"/api/v1/chat/conversations/{cid}/messages",
        headers=employee_headers,
        json={"content": "I entered my password on a phishing page."},
    )
    assert result.status_code == 200, result.text
    payload = result.json()["assistant_message"]["payload"]
    assert payload["ticket_reference"] and payload["provider"] == "offline-fallback"
    assert payload["model_usage"]["network_calls"] == 1
    assert payload["model_usage"]["budget_exhausted"]


@pytest.mark.parametrize(
    "vectors", [[], [[1, 2]], [[0, 0, 0]], [[float("nan"), 1, 0]], [[float("inf"), 0, 1]]]
)
def test_invalid_embedding_vectors_are_rejected(monkeypatch, vectors):
    provider = OpenAICompatibleEmbeddingProvider(
        api_key="synthetic", base_url="https://provider.invalid/v1", model="synthetic", dimension=3
    )
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(
            200,
            request=httpx.Request("POST", "https://provider.invalid/v1/embeddings"),
            content=json.dumps({"data": [{"embedding": v} for v in vectors]}).encode(),
        ),
    )
    with pytest.raises(UpstreamServiceError):
        provider.embed(["Synthetic text"])


def test_embedding_indexes_keep_inputs_matched_with_the_correct_vectors(monkeypatch):
    provider = OpenAICompatibleEmbeddingProvider(
        api_key="synthetic", base_url="https://provider.invalid/v1", model="synthetic", dimension=3
    )
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(
            200,
            request=httpx.Request("POST", "https://provider.invalid/v1/embeddings"),
            json={
                "data": [{"index": 1, "embedding": [0, 1, 0]}, {"index": 0, "embedding": [1, 0, 0]}]
            },
        ),
    )
    assert provider.embed(["First input", "Second input"]) == [[1, 0, 0], [0, 1, 0]]
