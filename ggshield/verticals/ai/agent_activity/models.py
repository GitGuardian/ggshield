"""Wire shape for raw history events sent to the GitGuardian API."""

from dataclasses import asdict, dataclass
from typing import Dict


@dataclass(frozen=True)
class AgentActivityEvent:
    """One raw record from an agent's transcript or database.

    Fields:
    - agent_name: short agent identifier matching Agent.name (e.g. "claude-code").
    - source_kind: agent-scoped identifier for the file/table the record came from
      (e.g. "5_session_transcript", "6_composer_bubble").
    - source_path: on-disk path relative to the agent's config dir, with variable
      parts (session UUIDs, workspace hashes) preserved.
    - record_offset: stable string identifier of the record within its source file.
      Line index serialised as a string ("0", "1", …) for JSONL and JSON files.
      For SQLite, the value(s) of the declared key_columns — single column: the
      column value; multiple columns: a JSON-encoded list. Subclasses may override
      ActivitySource.record_offset for non-trivial cases.
    - content: the record serialised as a string. JSONL and JSON files: the raw
      line or file text verbatim. SQLite rows: the row dict serialised with
      json.dumps (default) or a custom per-source filter.
    """

    agent_name: str
    source_kind: str
    source_path: str
    record_offset: str
    content: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)
