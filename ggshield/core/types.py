from dataclasses import fields
from typing import Any, Dict, Optional

import marshmallow_dataclass
from marshmallow.decorators import pre_load
from pygitguardian.models_utils import FromDictMixin, ToDictMixin

from ggshield.core import ui


@marshmallow_dataclass.dataclass
class FilteredConfig(FromDictMixin, ToDictMixin):
    @classmethod
    @pre_load(pass_many=False)
    def filter_fields(cls, data: Dict[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """
        Remove and alert on unknown fields.
        """
        field_names = {field_.name for field_ in fields(cls)}
        filtered_fields = {}
        for key, item in data.items():
            if key in field_names:
                filtered_fields[key] = item
            else:
                ui.display_warning(f"Unrecognized key in config: {key}")

        return filtered_fields


@marshmallow_dataclass.dataclass
class IgnoredMatch(FilteredConfig):
    match: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = ""


IgnoredMatch.SCHEMA = marshmallow_dataclass.class_schema(IgnoredMatch)()
