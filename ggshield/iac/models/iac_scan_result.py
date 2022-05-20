from typing import Any, Dict

from marshmallow import fields, post_load
from pygitguardian.models import ScanResult, ScanResultSchema

from ggshield.iac.models.iac_policy_break import IaCPolicyBreakSchema


class IaCScanResultSchema(ScanResultSchema):
    policy_breaks = fields.List(fields.Nested(IaCPolicyBreakSchema), required=True)

    @post_load
    def make_scan_result(self, data: Dict[str, Any], **kwargs: Any) -> "IaCScanResult":
        return IaCScanResult(**data)


class IaCScanResult(ScanResult):
    SCHEMA = IaCScanResultSchema()
