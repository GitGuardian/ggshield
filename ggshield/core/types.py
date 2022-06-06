from dataclasses import dataclass
from typing import Optional

import marshmallow_dataclass


@dataclass
class IgnoredMatch:
    match: str
    name: Optional[str] = None

    def __post_init__(self) -> None:
        if self.name is None:
            self.name = ""


IgnoredMatchSchema = marshmallow_dataclass.class_schema(IgnoredMatch)
