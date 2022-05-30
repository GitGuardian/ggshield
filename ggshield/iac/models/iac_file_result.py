from dataclasses import dataclass
from typing import List

import marshmallow_dataclass
from pygitguardian.models import Base, BaseSchema

from ggshield.iac.models.iac_vulnerability import IaCVulnerability


@dataclass
class IaCFileResult(Base):
    filename: str
    incidents: List[IaCVulnerability]


IaCFileResultSchema = marshmallow_dataclass.class_schema(IaCFileResult, BaseSchema)
