from typing import Optional

import marshmallow_dataclass
from marshmallow import EXCLUDE


@marshmallow_dataclass.dataclass
class IgnoredMatch:
    class Meta:
        unknown = EXCLUDE

    match: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = ""


IgnoredMatchSchema = marshmallow_dataclass.class_schema(IgnoredMatch)
