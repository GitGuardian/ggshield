from dataclasses import dataclass
from typing import List

import marshmallow_dataclass
from pygitguardian.models import Base, BaseSchema


@dataclass
class IaCScanResult(Base):
    iac_engine_version: str
    entities_with_incidents: List["IaCVulnerability"]
    id: str = ""
    type: str = ""


@dataclass
class IaCVulnerability:
    filename: str
    policy: str
    policy_id: str
    line_end: int
    line_start: int
    description: str
    documentation_url: str
    component: str = ""
    severity: str = ""
    ignore_sha: str = ""


IaCScanResultSchema = marshmallow_dataclass.class_schema(IaCScanResult, BaseSchema)
IaCVulnerabilitiesSchema = marshmallow_dataclass.class_schema(IaCVulnerability)
