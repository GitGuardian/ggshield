from dataclasses import dataclass, field
from typing import List

import marshmallow_dataclass


@dataclass
class IaCConfig:
    """
    Holds the iac config as defined .gitguardian.yaml files
    (local and global).
    """

    ignored_paths: List[str] = field(default_factory=list)
    ignored_policies: List[str] = field(default_factory=list)
    minimum_severity: str = "LOW"


IaCConfigSchema = marshmallow_dataclass.class_schema(IaCConfig)
