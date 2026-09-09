from guardian.models import Alert, TriageResult
from guardian.store import InMemoryStore


def _result(source_id: str, status: str = "triaged") -> TriageResult:
    return TriageResult(
        alert=Alert(source="sentinelone", source_id=source_id, title=f"a{source_id}"),
        status=status,
    )


async def test_roundtrip_and_dedupe_tracking():
    store = InMemoryStore()
    result = _result("1")
    await store.put(result)

    assert (await store.get(result.alert.id)) is result
    assert await store.has_seen("sentinelone", "1")
    assert not await store.has_seen("sentinelone", "2")


async def test_list_is_newest_first():
    store = InMemoryStore()
    for i in range(3):
        await store.put(_result(str(i)))

    assert [r.alert.source_id for r in await store.list()] == ["2", "1", "0"]


async def test_eviction_drops_oldest_and_forgets_it():
    store = InMemoryStore(max_items=2)
    for i in range(3):
        await store.put(_result(str(i)))

    assert len(await store.list()) == 2
    assert not await store.has_seen("sentinelone", "0")
    assert await store.has_seen("sentinelone", "2")


async def test_failed_triage_is_not_marked_seen():
    """A transient failure must stay eligible for retry, not be skipped forever."""
    store = InMemoryStore()
    await store.put(_result("1", status="failed"))

    assert not await store.has_seen("sentinelone", "1")


async def test_refusal_is_terminal():
    """A refusal needs a human, not a retry - retrying just burns tokens."""
    store = InMemoryStore()
    await store.put(_result("1", status="refused"))

    assert await store.has_seen("sentinelone", "1")


async def test_retry_supersedes_the_failed_attempt():
    store = InMemoryStore()
    failed = _result("1", status="failed")
    await store.put(failed)

    retry = _result("1", status="triaged")
    await store.put(retry)

    assert await store.has_seen("sentinelone", "1")
    assert (await store.get(failed.alert.id)) is None
    assert len(await store.list()) == 1


async def test_reused_alert_id_does_not_leave_a_stale_source_mapping():
    """/v1/alerts accepts caller-supplied IDs; two source alerts sharing one
    must not make the first look seen and hand back the second's result."""
    store = InMemoryStore()
    first = Alert(id="shared", source="m", source_id="one", title="one")
    second = Alert(id="shared", source="m", source_id="two", title="two")

    await store.put(TriageResult(alert=first, status="triaged"))
    await store.put(TriageResult(alert=second, status="triaged"))

    assert await store.has_seen("m", "one") is False
    assert await store.get_by_source("m", "one") is None
    assert await store.has_seen("m", "two") is True


async def test_source_keys_do_not_collide_on_the_separator():
    """Both parts are caller-controlled; ("a:b", "c") and ("a", "b:c") are
    different alerts and must not share a dedupe record."""
    store = InMemoryStore()
    first = Alert(source="a:b", source_id="c", title="first")
    await store.put(TriageResult(alert=first, status="triaged"))

    assert await store.has_seen("a:b", "c") is True
    assert await store.has_seen("a", "b:c") is False
    assert await store.get_by_source("a", "b:c") is None
