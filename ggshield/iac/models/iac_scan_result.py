from dataclasses import dataclass, field
from typing import List

import marshmallow_dataclass
from pygitguardian.models import Base, BaseSchema

from ggshield.iac.models.iac_file_result import IaCFileResult


@dataclass
class IaCScanResult(Base):
    id: str = ""
    type: str = ""
    iac_engine_version: str = ""
    entities_with_incidents: List[IaCFileResult] = field(default_factory=list)


IaCScanResultSchema = marshmallow_dataclass.class_schema(IaCScanResult, BaseSchema)
