"""The cursor store is a best-effort JSON file in the (autouse-isolated) cache
dir, scoped per credential. See cursors.py."""

from types import SimpleNamespace

from ggshield.verticals.ai.agent_activity.cursors import (
    NOTHING,
    CursorStore,
    scope_for,
)


def _client(base_uri="https://api.gg.com", api_key="tok-abc"):
    return SimpleNamespace(base_uri=base_uri, api_key=api_key)


def test_scope_is_stable_and_credential_specific():
    base = scope_for(_client())
    assert base == scope_for(_client())  # deterministic
    assert base != scope_for(_client(api_key="other"))  # key changes it
    assert base != scope_for(_client(base_uri="https://eu.gg.com"))  # instance too
    assert "tok-abc" not in base  # raw key never embedded


def test_get_missing_returns_nothing():
    store = CursorStore.load()
    assert store.get("s", "claude-code", "session_transcript", "p.jsonl") == NOTHING


def test_advance_and_get_roundtrip():
    store = CursorStore.load()
    store.advance("s", "claude-code", "session_transcript", "p.jsonl", 7)
    assert store.get("s", "claude-code", "session_transcript", "p.jsonl") == 7


def test_advance_never_goes_backwards():
    store = CursorStore.load()
    store.advance("s", "a", "k", "p", 10)
    store.advance("s", "a", "k", "p", 4)  # lower index is ignored
    assert store.get("s", "a", "k", "p") == 10


def test_save_then_reload_persists():
    store = CursorStore.load()
    store.advance("s", "a", "k", "p", 3)
    store.save()
    assert CursorStore.load().get("s", "a", "k", "p") == 3


def test_scopes_are_isolated():
    store = CursorStore.load()
    store.advance("scope-1", "a", "k", "p", 5)
    assert store.get("scope-2", "a", "k", "p") == NOTHING


def test_corrupt_file_is_fail_open():
    store = CursorStore.load()
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{ this is not json", encoding="utf-8")
    # Loading garbage yields an empty store instead of raising.
    assert CursorStore.load().get("s", "a", "k", "p") == NOTHING


def test_save_is_fail_open_on_oserror():
    store = CursorStore.load()
    store.advance("s", "a", "k", "p", 1)
    # Make the cache dir path an existing file so the atomic write cannot create
    # it; save() must swallow the OSError rather than propagate it.
    store.path.parent.write_text("not a directory", encoding="utf-8")
    store.save()  # does not raise
