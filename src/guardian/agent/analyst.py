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

# Server-side refusal fallbacks (see module docstring).
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class RefusedError(Exception):
    """The model declined to analyze this alert.

    Distinct from a failure: a refusal is a policy decision that needs a human,
    whereas a failure is something to retry or fix. Raised only on an actual
    `stop_reason == "refusal"` - an empty or malformed response is a failure.
    """


class Analyst:
    def __init__(
        self,
        settings: Settings,
        store: InMemoryStore,
        client: AsyncAnthropic | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        # An explicit key covers the documented .env flow; without one, zero-arg
        # construction lets the SDK resolve ANTHROPIC_API_KEY or an
        # `ant auth login` profile itself.
        if client is not None:
            self.client = client
        elif settings.anthropic_api_key:
            self.client = AsyncAnthropic(api_key=settings.anthropic_api_key)
        else:
            self.client = AsyncAnthropic()
            if self.client.api_key is None and self.client.auth_token is None:
                # Not fatal - the SDK may still resolve a profile at request
                # time - but a deployment that simply forgot the key would
                # otherwise fail every triage until the alerts dead-letter.
                logger.warning(
                    "No ANTHROPIC_API_KEY configured; relying on the SDK's own "
                    "credential discovery. Every triage will fail if it finds none."
                )

    async def triage(self, alert: Alert) -> TriageResult:
        result = TriageResult(alert=alert, model=self.settings.model)
        call_log: list[str] = []
        tools = build_tools(self.store, call_log, current=alert)
        # Built once and shared by both phases: the verdict call must replay
        # the investigation's exact prefix for the prompt cache to hit and for
        # the verdict to be grounded in the same alert rendering.
        system, opening = self._conversation(alert)

        try:
            investigation = await self._investigate(system, opening, tools)
            result.verdict = await self._render_verdict(system, opening, investigation)
            result.status = "triaged"
        except RefusedError as exc:
            logger.warning("Triage refused for alert %s: %s", alert.id, exc)
            result.status = "refused"
            result.error = f"{exc}; needs human review."
        except Exception as exc:  # surfaced on the result, never swallowed
            logger.exception("Triage failed for alert %s", alert.id)
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.enrichment_log = call_log
            result.triaged_at = datetime.now(UTC)

        return result

    @staticmethod
    def _conversation(alert: Alert) -> tuple[list[dict], dict]:
        """The shared prefix of both model calls: system block and opening turn.

        The frozen system prompt goes first so it forms a stable, cacheable
        prefix across every alert; the volatile alert body goes in the user
        turn, fenced as untrusted data.
        """
        system = [
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        opening = {
            "role": "user",
            "content": TRIAGE_INSTRUCTION.format(alert=fence_alert(alert.summary())),
        }
        return system, opening

    async def _investigate(self, system: list[dict], opening: dict, tools: list) -> str:
        """Run the enrichment tool loop and return the investigation text.

        Raises:
            RefusedError: the model declined to analyze the alert.
            RuntimeError: the turn ended without usable text, e.g. it hit
                `max_tokens` before writing any, or the tool loop hit its
                iteration ceiling. Those are failures to fix, not refusals,
                so they must not be reported as one.
        """
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
            # The runner returns mid-loop only when it hit `max_iterations`.
            raise RuntimeError(
                f"Investigation exceeded {self.settings.max_tool_iterations} tool iterations"
            )

        text = "\n".join(b.text for b in final.content if b.type == "text").strip()
        if not text:
            raise RuntimeError(f"Investigation returned no text (stop_reason={final.stop_reason})")
        return text

    async def _render_verdict(
        self, system: list[dict], opening: dict, investigation: str
    ) -> Verdict:
        """Convert the investigation into a schema-valid verdict.

        Raises:
            RefusedError: the model declined to produce a verdict.
            RuntimeError: the response carried no parsable verdict.
        """
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

        # `parsed_output` is None when the response carried no text block at all;
        # malformed JSON raises during validation and lands in the failure path.
        if response.parsed_output is None:
            raise RuntimeError(
                f"Verdict response contained no parsable output "
                f"(stop_reason={response.stop_reason})"
            )
        return response.parsed_output
