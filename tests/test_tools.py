"""Enrichment tool tests."""

from datetime import datetime

from guardian.agent.tools import build_tools
from guardian.models import Alert, TriageResult
from guardian.store import InMemoryStore


def _tool(tools, name):
    return next(t for t in tools if t.name == name)


async def test_search_related_alerts_handles_a_naive_timestamp():
    """A manually posted alert with no UTC offset must not break enrichment.

    Comparing a naive datetime against an aware cutoff raises TypeError, which
    would surface as a failed triage rather than a missing-context result.
    """
    store = InMemoryStore()
    await store.put(
        TriageResult(
            alert=Alert(
                source="manual",
                title="Naive",
                observed_at=datetime(2026, 9, 9, 12, 0, 0),  # noqa: DTZ001 - naive is the point
                host={"hostname": "WIN-1"},
            ),
            status="triaged",
        )
    )
    tool = _tool(build_tools(store, []), "search_related_alerts")

    result = await tool(hostname="WIN-1", hours=24 * 3650)

    assert "WIN-1" in result


async def test_search_related_alerts_records_the_call_for_audit():
    store = InMemoryStore()
    log: list[str] = []
    tool = _tool(build_tools(store, log), "search_related_alerts")

    await tool(hostname="WIN-2")

    assert log and "search_related_alerts" in log[0]
