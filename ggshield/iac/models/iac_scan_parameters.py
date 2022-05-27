from dataclasses import dataclass, field
from typing import List, Optional

import marshmallow_dataclass
from pygitguardian.models import Base, BaseSchema


@dataclass
class IaCScanParameters(Base):
    ignored_policies: List[str] = field(default_factory=list)
    minimum_severity: Optional[str] = None


IaCScanParametersSchema = marshmallow_dataclass.class_schema(
    IaCScanParameters, BaseSchema
)
