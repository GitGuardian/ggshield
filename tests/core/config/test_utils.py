from dataclasses import dataclass, field
from typing import Set

from ggshield.core.config.utils import custom_asdict, replace_in_keys


class TestUtils:
    def test_replace_in_keys(self):
        data = {"last-found-secrets": {"XXX"}}
        replace_in_keys(data, "-", "_")
        assert data == {"last_found_secrets": {"XXX"}}
        replace_in_keys(data, "_", "-")
        assert data == {"last-found-secrets": {"XXX"}}

    def test_custom_asdict_turns_set_into_list(self):
        """
        GIVEN an object containing a set
        WHEN calling test_custom_asdict() on it
        THEN the set is turned into a list
        """

        @dataclass
        class TestObject:
            data: Set[str] = field(default_factory=set)

        obj = TestObject(data={"a", "c", "b"})

        dct = custom_asdict(obj, root=True)

        assert isinstance(dct["data"], list)
        assert sorted(dct["data"]) == ["a", "b", "c"]
