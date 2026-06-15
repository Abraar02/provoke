"""Native Anthropic Messages API target.

The OpenAI-compatible adapter covers most providers, but Anthropic's native API
differs enough to warrant a first-class adapter: the system prompt is a separate
top-level field (not a message), and responses are a list of content blocks. The
API key is read from an environment variable named in config; it is masked in
the repr. A single AsyncClient is pooled and closed via aclose().
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

import httpx

from provoke.models import Message
from provoke.targets.base import TargetError

DEFAULT_BASE_URL = "https://api.anthropic.com"
DEFAULT_VERSION = "2023-06-01"


@dataclass(slots=True)
class AnthropicTarget:
    name: str
    model: str
    api_key: str | None = None
    base_url: str = DEFAULT_BASE_URL
    anthropic_version: str = DEFAULT_VERSION
    temperature: float = 0.0
    max_tokens: int = 512
    timeout_s: float = 30.0
    _client: httpx.AsyncClient | None = field(default=None, init=False, repr=False)

    def __repr__(self) -> str:
        masked = "***" if self.api_key else None
        return (
            f"AnthropicTarget(name={self.name!r}, model={self.model!r}, "
            f"api_key={masked!r})"
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
        system = "\n".join(m.content for m in messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]
        payload: dict[str, object] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": turns,
        }
        if system:
            payload["system"] = system

        headers = {
            "content-type": "application/json",
            "anthropic-version": self.anthropic_version,
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        url = self.base_url.rstrip("/") + "/v1/messages"
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
        except ValueError as exc:
            raise TargetError(f"{self.name}: invalid JSON response") from exc

        return _extract_text(data, self.name)


def _extract_text(data: object, name: str) -> str:
    try:
        blocks = data["content"]  # type: ignore[index]
    except (KeyError, TypeError) as exc:
        raise TargetError(f"{name}: unexpected response shape") from exc
    parts = [
        block["text"]
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text"
    ]
    if not parts:
        raise TargetError(f"{name}: no text content in response")
    return "".join(parts)
