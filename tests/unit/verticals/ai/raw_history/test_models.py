import json

from ggshield.verticals.ai.raw_history.models import RawHistoryEvent


def test_raw_history_event_to_dict_is_json_serializable() -> None:
    raw_content = json.dumps(
        {"key": "bubbleId:0b1f32eb:abc123", "value": '{"role":"user"}'}
    )
    e = RawHistoryEvent(
        agent_name="cursor",
        source_kind="composer_bubble",
        source_path="globalStorage/state.vscdb",
        record_offset="bubbleId:0b1f32eb:abc123",
        content=raw_content,
    )
    payload = e.to_dict()
    assert payload == {
        "agent_name": "cursor",
        "source_kind": "composer_bubble",
        "source_path": "globalStorage/state.vscdb",
        "record_offset": "bubbleId:0b1f32eb:abc123",
        "content": raw_content,
    }
    assert json.loads(json.dumps(payload)) == payload
