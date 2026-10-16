"""Model backends.

Any serving stack that exposes the OpenAI ``/v1/chat/completions`` API works:
llama.cpp ``llama-server``, vLLM, SGLang, TGI, Ollama, LM Studio. That is the
intended way to plug in proprietary 2B-3B models (including LoRA fine-tunes):
serve them locally, point ``--model-url`` at the server. Nothing leaves the host.

To add a backend that is not OpenAI-compatible, implement ``ModelBackend``.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Protocol

from .verdict import SCHEMA


class BackendUnavailable(Exception):
    """The model server could not be reached; the caller should retry later."""


class ModelBackend(Protocol):
    name: str

    def complete(self, messages: List[Dict[str, str]]) -> str:
        """Return the raw text of the model's reply."""


class OpenAICompatBackend:
    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None,
                 timeout: float = 60.0, max_tokens: int = 512, json_mode: str = "schema",
                 retries: int = 2, transport: Optional["httpx.BaseTransport"] = None):
        import httpx  # lazy: the simulated demo runs without it

        if json_mode not in ("schema", "object", "none"):
            raise ValueError("json_mode must be schema, object or none")
        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.json_mode = json_mode
        self.retries = retries
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers,
                                    timeout=timeout, transport=transport)

    def _body(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self.max_tokens,
        }
        if self.json_mode == "schema":
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "triage_verdict", "strict": True, "schema": SCHEMA},
            }
        elif self.json_mode == "object":
            body["response_format"] = {"type": "json_object"}
        return body

    def complete(self, messages: List[Dict[str, str]]) -> str:
        import httpx

        last_error: Exception = BackendUnavailable("no attempt made")
        for attempt in range(self.retries + 1):
            try:
                resp = self._client.post("/chat/completions", json=self._body(messages))
            except httpx.TransportError as exc:
                last_error = exc
            else:
                if resp.status_code < 500:
                    resp.raise_for_status()
                    return resp.json()["choices"][0]["message"]["content"] or ""
                last_error = httpx.HTTPStatusError(f"server error {resp.status_code}",
                                                   request=resp.request, response=resp)
            if attempt < self.retries:
                time.sleep(2 ** attempt)
        raise BackendUnavailable(str(last_error)) from last_error

    def close(self) -> None:
        self._client.close()
