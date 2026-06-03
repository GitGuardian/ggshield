import json

from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent


def test_agent_activity_event_to_dict_is_json_serializable() -> None:
    raw_content = json.dumps(
        {"key": "bubbleId:0b1f32eb:abc123", "value": '{"role":"user"}'}
    )
    e = AgentActivityEvent(
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
