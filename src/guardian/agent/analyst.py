"""Provider-neutral analyst agent for OpenAI-compatible and Anthropic APIs."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

from anthropic import AsyncAnthropic
from openai import APIError, AsyncOpenAI

from guardian.agent.prompts import (
    SYSTEM_PROMPT,
    TRIAGE_INSTRUCTION,
    VERDICT_INSTRUCTION,
    fence_alert,
)
from guardian.agent.tools import build_tools
from guardian.config import Settings
from guardian.models import Alert, TriageResult, Verdict
from guardian.store import InMemoryStore

logger = logging.getLogger(__name__)
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class RefusedError(Exception):
    """The configured model declined to analyze the alert."""


class Analyst:
    """Run the same investigation/verdict flow through either provider protocol."""

    def __init__(self, settings: Settings, store: InMemoryStore, client: Any | None = None):
        self.settings = settings
        self.store = store
        self.client = client
        if client is not None:
            return
        if not settings.provider or not settings.base_url or not settings.model:
            logger.warning(
                "Model provider is not configured; set GUARDIAN_PROVIDER, "
                "GUARDIAN_BASE_URL, and GUARDIAN_MODEL before triage."
            )
            return
        if settings.model_api_key and not settings.base_url.lower().startswith("https://"):
            raise ValueError("A model API key requires an HTTPS GUARDIAN_BASE_URL")
        if settings.provider == "anthropic":
            kwargs: dict[str, Any] = {}
            if settings.model_api_key:
                kwargs["api_key"] = settings.model_api_key
            if settings.base_url:
                kwargs["base_url"] = settings.base_url
            self.client = AsyncAnthropic(**kwargs)
        else:
            # The OpenAI SDK requires a key even for local servers. A dummy
            # value keeps keyless localhost development possible; hosted
            # endpoints still require a real key in normal operation.
            kwargs = {
                "base_url": settings.base_url,
                "api_key": settings.model_api_key or "not-needed",
            }
            self.client = AsyncOpenAI(**kwargs)

    async def triage(self, alert: Alert) -> TriageResult:
        result = TriageResult(alert=alert, model=self.settings.model or None)
        call_log: list[str] = []
        tools = build_tools(self.store, call_log, current=alert)
        system, opening = self._conversation(alert)
        try:
            if self.client is None:
                raise RuntimeError(
                    "Model provider is not configured; set GUARDIAN_PROVIDER, "
                    "GUARDIAN_BASE_URL, and GUARDIAN_MODEL"
                )
            if self.settings.provider == "anthropic":
                investigation = await self._investigate_anthropic(system, opening, tools)
                result.verdict = await self._render_anthropic(system, opening, investigation)
            else:
                investigation = await self._investigate_openai(system, opening, tools)
                result.verdict = await self._render_openai(system, opening, investigation)
            result.status = "triaged"
        except RefusedError as exc:
            result.status = "refused"
            result.error = f"{exc}; needs human review."
        except Exception as exc:
            logger.exception("Triage failed for alert %s", alert.id)
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.enrichment_log = call_log
            result.triaged_at = datetime.now(UTC)
        return result

    @staticmethod
    def _conversation(alert: Alert) -> tuple[list[dict], dict]:
        system = [{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}]
        opening = {
            "role": "user",
            "content": TRIAGE_INSTRUCTION.format(alert=fence_alert(alert.summary())),
        }
        return system, opening

    async def _investigate_anthropic(self, system: list[dict], opening: dict, tools: list) -> str:
        runner = self.client.beta.messages.tool_runner(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            max_iterations=self.settings.max_tool_iterations,
            system=system,
            thinking={"type": "adaptive"},
            output_config={"effort": self.settings.effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
            tools=tools,
            messages=[opening],
        )
        final = await runner.until_done()
        if final.stop_reason == "refusal":
            category = getattr(final.stop_details, "category", None)
            raise RefusedError(f"Model declined to analyze this alert (category={category})")
        if final.stop_reason == "tool_use":
            raise RuntimeError(
                f"Investigation exceeded {self.settings.max_tool_iterations} tool iterations"
            )
        text = "\n".join(b.text for b in final.content if b.type == "text").strip()
        if not text:
            raise RuntimeError(f"Investigation returned no text (stop_reason={final.stop_reason})")
        return text

    async def _render_anthropic(
        self, system: list[dict], opening: dict, investigation: str
    ) -> Verdict:
        response = await self.client.messages.parse(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            system=system,
            thinking={"type": "adaptive"},
            messages=[
                opening,
                {"role": "assistant", "content": investigation},
                {"role": "user", "content": VERDICT_INSTRUCTION},
            ],
            output_format=Verdict,
        )
        if response.stop_reason == "refusal":
            category = getattr(response.stop_details, "category", None)
            raise RefusedError(f"Model declined to produce a verdict (category={category})")
        if response.parsed_output is None:
            raise RuntimeError(
                f"Verdict response contained no parsable output (stop_reason={response.stop_reason})"
            )
        return response.parsed_output

    @staticmethod
    def _openai_tools(tools: list) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.input_schema,
                },
            }
            for t in tools
        ]

    async def _investigate_openai(self, system: list[dict], opening: dict, tools: list) -> str:
        messages: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}, opening]
        tool_map = {t.name: t for t in tools}
        for round_number in range(self.settings.max_tool_iterations + 1):
            try:
                response = await self.client.chat.completions.create(
                    model=self.settings.model,
                    messages=messages,
                    tools=self._openai_tools(tools),
                    max_tokens=self.settings.max_tokens,
                )
            except APIError as exc:
                # Some compatible gateways expose chat completions but not
                # function calling. Retry once without tools so the core
                # triage path still works; other API errors must surface.
                details = str(exc).lower()
                tool_error = any(
                    term in details
                    for term in ("tool", "function calling", "unsupported parameter")
                )
                if getattr(exc, "status_code", None) not in (400, 404, 422) or not tool_error:
                    raise
                response = await self.client.chat.completions.create(
                    model=self.settings.model,
                    messages=messages,
                    max_tokens=self.settings.max_tokens,
                )
            message = response.choices[0].message
            if getattr(message, "refusal", None):
                raise RefusedError("Model declined to analyze this alert")
            messages.append(message.model_dump(exclude_none=True))
            if not message.tool_calls:
                text = (message.content or "").strip()
                if not text:
                    raise RuntimeError("Investigation returned no text")
                return text
            if round_number == self.settings.max_tool_iterations:
                raise RuntimeError(
                    f"Investigation exceeded {self.settings.max_tool_iterations} tool iterations"
                )
            for call in message.tool_calls:
                tool = tool_map.get(call.function.name)
                if tool is None:
                    raise RuntimeError(f"Model requested unknown tool {call.function.name!r}")
                try:
                    arguments = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        f"Invalid arguments for tool {call.function.name!r}"
                    ) from exc
                output = await tool.call(arguments)
                messages.append({"role": "tool", "tool_call_id": call.id, "content": str(output)})
        raise RuntimeError("Investigation did not produce a completion")

    async def _render_openai(
        self, system: list[dict], opening: dict, investigation: str
    ) -> Verdict:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            opening,
            {"role": "assistant", "content": investigation},
            {"role": "user", "content": VERDICT_INSTRUCTION},
        ]
        schema = {
            "type": "json_schema",
            "json_schema": {
                "name": "Verdict",
                "strict": True,
                "schema": Verdict.model_json_schema(),
            },
        }
        try:
            response = await self.client.chat.completions.create(
                model=self.settings.model,
                messages=messages,
                max_tokens=self.settings.max_tokens,
                response_format=schema,
            )
        except APIError as exc:
            # A number of OpenAI-compatible gateways support JSON mode but not
            # the newer json_schema response format. Do not mask auth, quota,
            # connectivity, or server failures with a second request.
            details = str(exc).lower()
            format_error = any(
                term in details
                for term in ("response_format", "json_schema", "structured output", "json schema")
            )
            if getattr(exc, "status_code", None) not in (400, 404, 422) or not format_error:
                raise
            response = await self.client.chat.completions.create(
                model=self.settings.model,
                messages=messages,
                max_tokens=self.settings.max_tokens,
                response_format={"type": "json_object"},
            )
        message = response.choices[0].message
        if getattr(message, "refusal", None):
            raise RefusedError("Model declined to produce a verdict")
        content = (message.content or "").strip()
        if not content:
            raise RuntimeError("Verdict response contained no parsable output")
        return Verdict.model_validate(json.loads(content))
