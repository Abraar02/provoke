"""Adapter for any OpenAI-compatible /chat/completions endpoint.

Works against OpenAI, Azure OpenAI, vLLM, Ollama, LM Studio, Together, Groq, and
the OpenAI-compatible endpoints most providers now expose — so a single adapter
covers the majority of real targets. The API key is read from an environment
variable named in config; it is never accepted as a literal in the config file.

A single AsyncClient is created lazily and reused across all attempts so the
connection pool (and TLS session) is shared — the point of the engine's bounded
concurrency. Call aclose() when finished; the engine does this automatically.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import httpx

from provoke.models import Message
from provoke.targets.base import TargetError


@dataclass(slots=True)
class OpenAICompatTarget:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    temperature: float = 0.0
    max_tokens: int = 512
    timeout_s: float = 30.0
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)

    def __repr__(self) -> str:
        # Never include the raw API key in repr/str — it can end up in logs.
        masked = "***" if self.api_key else None
        return (
            f"OpenAICompatTarget(name={self.name!r}, base_url={self.base_url!r}, "
            f"model={self.model!r}, api_key={masked!r})"
        )

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout_s)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def generate(self, messages: Sequence[Message]) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        url = self.base_url.rstrip("/") + "/chat/completions"
        try:
            response = await self._get_client().post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPStatusError as exc:
            raise TargetError(
                f"{self.name}: HTTP {exc.response.status_code} from {url}"
            ) from exc
        except httpx.HTTPError as exc:
            raise TargetError(f"{self.name}: request failed: {exc}") from exc
        except ValueError as exc:  # invalid JSON
            raise TargetError(f"{self.name}: invalid JSON response") from exc

        return _extract_content(data, self.name)


def _extract_content(data: object, name: str) -> str:
    try:
        choices = data["choices"]  # type: ignore[index]
        message = choices[0]["message"]
        content = message.get("content")
    except (KeyError, IndexError, TypeError) as exc:
        raise TargetError(f"{name}: unexpected response shape") from exc
    if not isinstance(content, str):
        raise TargetError(f"{name}: response content was not text")
    return content
