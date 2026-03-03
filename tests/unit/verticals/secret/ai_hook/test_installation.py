from copy import deepcopy
from typing import Any, Dict, List, Optional

import pytest

from ggshield.verticals.secret.ai_hook.installation import _fill_dict


def _locator(
    candidates: List[Dict[str, Any]], template: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """Locator that finds an object containing 'ggshield' or '<COMMAND>' in any value."""
    for obj in candidates:
        if isinstance(obj, dict):
            for v in obj.values():
                if "ggshield" in str(v) or "<COMMAND>" in str(v):
                    return obj
    return None


COMMAND = "ggshield secret scan ai-hook"


class TestFillDict:
    def test_empty_dict_fills_with_template_scalars(self):
        """Starting from an empty dict, scalar template entries are added."""
        start: Dict[str, Any] = {}
        template = {"a": 1, "b": "hello"}
        expected = {"a": 1, "b": "hello"}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 0}

    def test_empty_dict_fills_with_nested_dict(self):
        """Starting from an empty dict, nested dict template is merged recursively."""
        start: Dict[str, Any] = {}
        template = {"level1": {"level2": "x"}}
        expected = {"level1": {"level2": "x"}}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 0}

    def test_adding_keys_does_not_touch_existing(self):
        """Adding template keys leaves other existing keys unchanged."""
        start = {"other": 42, "nested": {"keep": True}}
        template = {"a": 1}
        expected = {"other": 42, "nested": {"keep": True}, "a": 1}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 0}

    def test_nested_dict_merges_without_overwriting_existing(self):
        """Nested template dict merges into existing nested dict, leaving existing keys."""
        start = {"level1": {"existing": 1}}
        template = {"level1": {"new": 2}}
        expected = {"level1": {"existing": 1, "new": 2}}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 0}

    def test_command_placeholder_replaced_by_command(self):
        """Template value '<COMMAND>' is replaced by the given command string."""
        start: Dict[str, Any] = {}
        template = {"cmd": "<COMMAND>"}
        expected = {"cmd": COMMAND}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 1, "already_present": 0}

    def test_overwrite_false_leaves_existing_scalar(self):
        """When overwrite is False, existing scalar value is left unchanged."""
        start = {"a": "existing"}
        template = {"a": "new"}
        expected = {"a": "existing"}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 0}

    def test_overwrite_true_replaces_existing_scalar(self):
        """When overwrite is True, existing scalar value is replaced by template."""
        start = {"a": "existing"}
        template = {"a": "new"}
        expected = {"a": "new"}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=True, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 0}

    def test_list_no_match_appends_new_object(self):
        """When locator finds no match in list, a new object is appended and filled."""
        start: Dict[str, Any] = {}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        expected = {"hooks": [{"command": COMMAND}]}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 1, "already_present": 0}

    def test_list_match_found_updates_existing_object_overwrite_true(self):
        """When locator finds a match in list, that object is updated (overwrite True)."""
        start = {"hooks": [{"command": "ggshield already"}]}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        expected = {"hooks": [{"command": COMMAND}]}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=True, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 1, "already_present": 1}

    def test_list_match_found_leaves_existing_object_overwrite_false(self):
        """When locator finds a match in list and overwrite is False, existing value is kept."""
        start = {"hooks": [{"command": "ggshield already"}]}
        template = {"hooks": [{"command": "<COMMAND>"}]}
        expected = {"hooks": [{"command": "ggshield already"}]}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        _fill_dict(
            config, template, COMMAND, overwrite=False, stats=stats, locator=_locator
        )
        assert config == expected
        assert stats == {"added": 0, "already_present": 1}

    def test_template_list_must_have_exactly_one_element(self):
        """Template list value must have exactly one element (raises ValueError otherwise)."""
        start: Dict[str, Any] = {}
        template = {"hooks": [{"a": 1}, {"b": 2}]}
        config = deepcopy(start)
        stats = {"added": 0, "already_present": 0}
        with pytest.raises(ValueError, match="Expected only one object in template"):
            _fill_dict(
                config,
                template,
                COMMAND,
                overwrite=False,
                stats=stats,
                locator=_locator,
            )
        assert stats == {"added": 0, "already_present": 0}
