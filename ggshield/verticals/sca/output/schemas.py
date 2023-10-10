from dataclasses import dataclass
from typing import cast

import marshmallow_dataclass
from pygitguardian.models import BaseSchema
from pygitguardian.sca_models import SCAScanAllOutput, SCAScanDiffOutput


@dataclass
class SCAJSONScanAllOutput(SCAScanAllOutput):
    total_vulns: int = 0


SCAJSONScanAllOutputSchema = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(SCAJSONScanAllOutput, base_schema=BaseSchema)(),
)


@dataclass
class SCAJSONScanDiffOutput(SCAScanDiffOutput):
    total_vulns: int = 0


SCAJSONScanDiffOutputSchema = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(SCAJSONScanDiffOutput, base_schema=BaseSchema)(),
)
