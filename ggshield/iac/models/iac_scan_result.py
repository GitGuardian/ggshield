from dataclasses import dataclass
from typing import List

import marshmallow_dataclass
from pygitguardian.models import Base, BaseSchema

from ggshield.iac.models.iac_file_result import IaCFileResult


@dataclass
class IaCScanResult(Base):
    iac_engine_version: str
    entities_with_incidents: List[IaCFileResult]
    id: str = ""
    type: str = ""


IaCScanResultSchema = marshmallow_dataclass.class_schema(IaCScanResult, BaseSchema)
