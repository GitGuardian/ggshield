from dataclasses import fields
from typing import Any, Dict, Optional

import marshmallow_dataclass
from marshmallow.decorators import pre_load
from pygitguardian.models import FromDictMixin, ToDictMixin

from ggshield.core.text_utils import display_warning


@marshmallow_dataclass.dataclass
class FilteredConfig(FromDictMixin, ToDictMixin):
    @classmethod
    @pre_load(pass_many=False)
    def filter_fields(cls, data: Dict, **kwargs: Any) -> Dict:
        """
        Remove and alert on unknown fields.
        """
        field_names = {field_.name for field_ in fields(cls)}
        filtered_fields = {}
        for key, item in data.items():
            filtered_key = key.replace("-", "_")
            if filtered_key in field_names:
                filtered_fields[filtered_key] = item
            else:
                display_warning(f"Unrecognized key in config: {key}")

        return filtered_fields


@marshmallow_dataclass.dataclass
class IgnoredMatch(FilteredConfig):
    match: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = ""


IgnoredMatch.SCHEMA = marshmallow_dataclass.class_schema(IgnoredMatch)()
