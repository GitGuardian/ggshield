"""`{{name}}` placeholders, replaced as plain text in both directions: expanded
in what a test feeds the command, collapsed back in what comes out."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List, Mapping, Tuple

from .environment import FAKE_API_KEY
from .sandbox import Sandbox


class Placeholders:
    def __init__(self, values: Mapping[str, str]):
        self._values = dict(values)
        # Every spelling of every value, longest first, so the most specific
        # placeholder wins ({{cache}}/... rather than {{tmp}}/cache/...).
        # Built once: collapse() runs on every request, output and written file.
        self._forms: List[Tuple[str, str]] = sorted(
            (
                (form, "{{" + name + "}}")
                for name, value in self._values.items()
                for form in _forms_of(value)
            ),
            key=lambda pair: len(pair[0]),
            reverse=True,
        )

    @classmethod
    def for_run(cls, sandbox: Sandbox, mock_url: str) -> Placeholders:
        return cls(
            {
                **{name: str(path) for name, path in sandbox.tracked().items()},
                "cache": str(sandbox.cache),
                # TMPDIR, and parent of all the above: longer paths are
                # replaced first, so it only catches what they don't
                "tmp": str(sandbox.root),
                "mock_url": mock_url,
                # The fake key: api_calls.yaml checks `Authorization: Token {{api_key}}`
                "api_key": FAKE_API_KEY,
            }
        )

    def expand(self, text: str) -> str:
        for name, value in self._values.items():
            text = text.replace("{{" + name + "}}", value)
        return text

    def expand_value(self, value):
        """Expand placeholders in a value loaded from YAML (str, list or dict)."""
        if isinstance(value, str):
            return self.expand(value)
        if isinstance(value, list):
            return [self.expand_value(v) for v in value]
        if isinstance(value, dict):
            return {
                self.expand_value(k): self.expand_value(v) for k, v in value.items()
            }
        return value

    def collapse(self, text: str) -> str:
        """Turn real values back into placeholders, longest form first."""
        for form, placeholder in self._forms:
            text = text.replace(form, placeholder)
        return text


def _forms_of(value: str) -> Iterable[str]:
    """The spellings a value can take in an output: paths have several."""
    forms = {value}
    path = Path(value)
    if path.is_absolute():
        # macOS: /var/folders/... is a symlink to /private/var/folders/...
        forms.add(str(path.resolve()))
        forms.add(path.as_posix())
        forms.add(path.resolve().as_posix())
    # JSON output escapes backslashes (Windows paths)
    forms |= {json.dumps(f)[1:-1] for f in list(forms)}
    return [f for f in forms if f]
