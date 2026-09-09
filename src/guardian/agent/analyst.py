"""The analyst agent: turns an `Alert` into a `TriageResult`.

Triage runs in two phases:

1. **Investigation** - an agentic tool loop where Claude enriches the alert
   using the tools in `tools.py` and reasons about what it found.
2. **Verdict** - a single structured-output call that converts that
   investigation into a validated `Verdict`. Keeping the verdict separate means
   the stored disposition is always schema-valid and directly comparable across
   alerts, rather than parsed out of prose.

Alert content is exactly the kind of material Claude's safety classifiers may
decline (malware names, attacker commands), so both phases check for
`stop_reason == "refusal"` and the investigation phase enables server-side
fallbacks, which re-runs a declined request on a fallback model inside the same
call. A refusal is surfaced as `status="refused"` for human review - never as a
clean verdict.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from anthropic import AsyncAnthropic

from guardian.agent.prompts import SYSTEM_PROMPT, TRIAGE_INSTRUCTION, VERDICT_INSTRUCTION
from guardian.agent.tools import build_tools
from guardian.config import Settings
from guardian.models import Alert, TriageResult, Verdict
from guardian.store import InMemoryStore

logger = logging.getLogger(__name__)

# Server-side refusal fallbacks (see module docstring).
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class Analyst:
    def __init__(
        self,
        settings: Settings,
        store: InMemoryStore,
        client: AsyncAnthropic | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        # Zero-arg construction resolves ANTHROPIC_API_KEY or an `ant auth login`
        # profile from the environment.
        self.client = client or AsyncAnthropic()

    async def triage(self, alert: Alert) -> TriageResult:
        result = TriageResult(alert=alert, model=self.settings.model)
        call_log: list[str] = []
        tools = build_tools(self.store, call_log)

        try:
            investigation = await self._investigate(alert, tools)
            if investigation is None:
                result.status = "refused"
                result.error = "Model declined to analyze this alert; needs human review."
                return result

            verdict = await self._render_verdict(alert, investigation)
            if verdict is None:
                result.status = "refused"
                result.error = "Model declined to produce a verdict; needs human review."
                return result

            result.verdict = verdict
            result.status = "triaged"
        except Exception as exc:  # surfaced on the result, never swallowed
            logger.exception("Triage failed for alert %s", alert.id)
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.enrichment_log = call_log
            result.triaged_at = datetime.now(UTC)

        return result

    async def _investigate(self, alert: Alert, tools: list) -> str | None:
        """Run the enrichment tool loop. Returns the investigation text, or None if refused."""
        runner = self.client.beta.messages.tool_runner(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            # Frozen system prompt first so it forms a stable, cacheable prefix
            # across every alert; the volatile alert body goes in `messages`.
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            thinking={"type": "adaptive"},
            output_config={"effort": self.settings.effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
            tools=tools,
            messages=[
                {"role": "user", "content": TRIAGE_INSTRUCTION.format(alert=alert.summary())}
            ],
        )

        final = await runner.until_done()
        if final.stop_reason == "refusal":
            logger.warning(
                "Investigation refused for alert %s (%s)",
                alert.id,
                getattr(final.stop_details, "category", None),
            )
            return None

        text = "\n".join(b.text for b in final.content if b.type == "text").strip()
        return text or None

    async def _render_verdict(self, alert: Alert, investigation: str) -> Verdict | None:
        """Convert the investigation into a schema-valid verdict."""
        response = await self.client.messages.parse(
            model=self.settings.model,
            max_tokens=self.settings.max_tokens,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            thinking={"type": "adaptive"},
            messages=[
                {"role": "user", "content": TRIAGE_INSTRUCTION.format(alert=alert.summary())},
                {"role": "assistant", "content": investigation},
                {"role": "user", "content": VERDICT_INSTRUCTION},
            ],
            output_format=Verdict,
        )
        if response.stop_reason == "refusal":
            logger.warning("Verdict refused for alert %s", alert.id)
            return None
        return response.parsed_output
