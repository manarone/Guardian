from guardian.models import Alert, TriageResult
from guardian.store import InMemoryStore


def _result(source_id: str) -> TriageResult:
    return TriageResult(
        alert=Alert(source="sentinelone", source_id=source_id, title=f"a{source_id}")
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
