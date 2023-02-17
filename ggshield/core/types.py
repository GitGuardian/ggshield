from dataclasses import fields
from typing import Any, Dict, Optional

import marshmallow_dataclass
from marshmallow.decorators import pre_load

from ggshield.core.errors import ParseError
from ggshield.core.text_utils import display_warning


@marshmallow_dataclass.dataclass
class ValidatedConfig:
    @classmethod
    def validate_fields(cls, data: Dict[str, Any], **kwargs: Any) -> None:
        """
        Raise exception on unknown keys
        """
        field_names = {field_.name for field_ in fields(cls)}
        hyphen_names = {name.replace("_", "-") for name in field_names}
        valid_names = field_names.union(hyphen_names)
        valid_names.add("version")
        for key in data.keys():
            if key not in valid_names:
                raise ParseError("Unrecognized key in config: {}".format(key))


@marshmallow_dataclass.dataclass
class FilteredConfig:
    @classmethod
    @pre_load(pass_many=False)
    def filter_fields(cls, data: Dict, **kwargs: Any) -> Dict:
        """
        Remove and alert on unknown fields.
        """
        field_names = {field_.name for field_ in fields(cls)}
        filtered_fields = {}
        for key, item in data.items():
            if key in field_names:
                filtered_fields[key] = item
            else:
                display_warning("Unrecognized key in config: {}".format(key))

        return filtered_fields


@marshmallow_dataclass.dataclass
class IgnoredMatch(FilteredConfig):

    match: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = ""


IgnoredMatchSchema = marshmallow_dataclass.class_schema(IgnoredMatch)
