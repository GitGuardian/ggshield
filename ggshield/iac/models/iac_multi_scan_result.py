from typing import Any, Dict

from marshmallow import fields, post_load, validate
from pygitguardian.models import MultiScanResult, MultiScanResultSchema

from ggshield.iac.models import IaCScanResultSchema


class IaCMultiScanResultSchema(MultiScanResultSchema):
    scan_results = fields.List(
        fields.Nested(IaCScanResultSchema),
        required=True,
        validates=validate.Length(min=1),
    )

    @post_load
    def make_scan_result(
        self, data: Dict[str, Any], **kwargs: Any
    ) -> "IaCMultiScanResult":
        return IaCMultiScanResult(**data)


class IaCMultiScanResult(MultiScanResult):
    SCHEMA = IaCMultiScanResultSchema()
