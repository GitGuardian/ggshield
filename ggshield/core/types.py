from dataclasses import fields
from typing import Any, Dict, List, Optional, Union

import marshmallow_dataclass
from marshmallow.decorators import pre_load

from ggshield.core.text_utils import display_warning


@marshmallow_dataclass.dataclass
class ValidatedConfig:
    @classmethod
    def validate_fields(cls, data: Union[Dict, List], **kwargs: Any) -> None:
        """
        Alert on unknown keys
        """
        field_names = {field_.name for field_ in fields(cls)}
        hyphen_names = {name_.replace("_", "-") for name_ in field_names}
        valid_names = field_names.union(hyphen_names)
        valid_names.add("version")
        if isinstance(data, dict):
            for key, value in list(data.items()):
                cls.validate_fields(value)
                if key not in valid_names:
                    display_warning(f"Unrecognized key in config: {key}")
        elif isinstance(data, list):
            for elem in data:
                cls.validate_fields(elem)


@marshmallow_dataclass.dataclass
class FilteredConfig:
    @classmethod
    @pre_load(pass_many=False)
    def filter_fields(cls, data: Dict, **kwargs: Any) -> Dict:
        """
        Remove unknown fields.
        """
        field_names = {field_.name for field_ in fields(cls)}
        filtered_fields = {}
        for key, item in data.items():
            if key in field_names:
                filtered_fields[key] = item

        return filtered_fields


@marshmallow_dataclass.dataclass
class IgnoredMatch(FilteredConfig):

    match: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = ""


IgnoredMatchSchema = marshmallow_dataclass.class_schema(IgnoredMatch)
