from dataclasses import dataclass, field
from typing import List, Type, cast

import marshmallow_dataclass
from marshmallow import fields
from pygitguardian.iac_models import (
    IaCDiffScanEntities,
    IaCDiffScanResult,
    IaCFileResult,
    IaCFileResultSchema,
    IaCScanResultSchema,
)
from pygitguardian.models import BaseSchema


@dataclass
class IaCJSONFileResult(IaCFileResult):
    total_incidents: int


class IaCJSONFileResultSchema(IaCFileResultSchema):
    total_incidents = fields.Integer(dump_default=0)


class IaCJSONScanResultSchema(IaCScanResultSchema):
    entities_with_incidents = fields.List(fields.Nested(IaCJSONFileResultSchema))
    total_incidents = fields.Integer(dump_default=0)


@dataclass
class IaCJSONScanDiffEntities(IaCDiffScanEntities):
    unchanged: List[IaCJSONFileResult] = field(default_factory=list)
    new: List[IaCJSONFileResult] = field(default_factory=list)
    deleted: List[IaCJSONFileResult] = field(default_factory=list)


@dataclass
class IaCJSONScanDiffResult(IaCDiffScanResult):
    entities_with_incidents: IaCJSONScanDiffEntities = field(
        default_factory=IaCJSONScanDiffEntities
    )


IaCJSONScanDiffResultSchema = cast(
    Type[BaseSchema],
    marshmallow_dataclass.class_schema(IaCJSONScanDiffResult, BaseSchema),
)
IaCJSONScanDiffResult.SCHEMA = IaCJSONScanDiffResultSchema()
