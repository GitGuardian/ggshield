"""test.yaml: how to run the command of one contract test.

    command: [api-status, --json]
    setup:                    # optional; commands run in {{work}} before it, git only
      - [git, init]
    env:                      # optional; a null value unsets the variable
      GITGUARDIAN_INSTANCE: null
    stdin: '...'              # optional

Values must be strings: YAML turns `5` into an int and `true` into a bool, and
converting them back (`True`) is a trap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .files import read_utf8


_ALLOWED_KEYS = {"command", "setup", "env", "stdin"}

# Programs a setup step may run
_SETUP_PROGRAMS = {"git"}


@dataclass
class Spec:
    command: List[str]
    setup: List[List[str]] = field(default_factory=list)
    env: Dict[str, Optional[str]] = field(default_factory=dict)
    stdin: Optional[str] = None


class SpecError(Exception):
    """test.yaml is invalid; the message lists every problem, one per line."""


def load(path: Path) -> Spec:
    data = yaml.safe_load(read_utf8(path)) or {}
    errors = validate(data)
    if errors:
        raise SpecError("\n".join(f"{path}: {error}" for error in errors))
    return Spec(
        command=data["command"],
        setup=data.get("setup") or [],
        env=data.get("env") or {},
        stdin=data.get("stdin"),
    )


def validate(spec: Any) -> List[str]:
    """Errors in a loaded test.yaml, empty when it is valid."""
    if not isinstance(spec, dict):
        return ["must be a mapping with a `command` key"]
    errors = []
    unknown = set(spec) - _ALLOWED_KEYS
    if unknown:
        errors.append(f"unknown keys {sorted(unknown)}")

    command = spec.get("command")
    if not isinstance(command, list) or not command:
        errors.append("`command` must be a non-empty list")
    else:
        for index, arg in enumerate(command):
            if not isinstance(arg, str):
                errors.append(_not_a_string(f"command argument {index}", arg))

    setup = spec.get("setup")
    if setup is not None:
        if not isinstance(setup, list):
            errors.append("`setup` must be a list of commands")
        else:
            for index, step in enumerate(setup):
                errors.extend(_validate_setup_step(index, step))

    env = spec.get("env")
    if env is not None:
        if not isinstance(env, dict):
            errors.append("`env` must be a mapping")
        else:
            for name, value in env.items():
                if value is not None and not isinstance(value, str):
                    errors.append(
                        _not_a_string(f"env value for {name}", value, nullable=True)
                    )

    stdin = spec.get("stdin")
    if stdin is not None and not isinstance(stdin, str):
        errors.append(_not_a_string("stdin", stdin))
    return errors


def _validate_setup_step(index: int, step: Any) -> List[str]:
    if not isinstance(step, list) or not step:
        return [f"setup step {index} must be a non-empty list"]
    errors = [
        _not_a_string(f"setup step {index} argument {position}", arg)
        for position, arg in enumerate(step)
        if not isinstance(arg, str)
    ]
    if step[0] not in _SETUP_PROGRAMS:
        errors.append(
            f"setup step {index} must run one of {sorted(_SETUP_PROGRAMS)},"
            f" got {step[0]!r}"
        )
    return errors


def _not_a_string(what: str, value: Any, nullable: bool = False) -> str:
    expected_type = "a string or null" if nullable else "a string"
    # The value YAML produced, not a suggestion: `0600` became 384 and `on`
    # became True, so only the author knows the text to quote.
    return (
        f"{what} must be {expected_type}, got {type(value).__name__} {value!r}:"
        " quote it as written in test.yaml"
    )
