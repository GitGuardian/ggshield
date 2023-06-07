from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import marshmallow_dataclass
from pygitguardian.iac_models import IaCFileResult, IaCScanParameters
from pygitguardian.models import Base, BaseSchema, Detail


# TODO: move these into pygitguardian


@dataclass
class IaCDiffScanEntities(Base):
    unchanged: List[IaCFileResult] = field(default_factory=list)
    new: List[IaCFileResult] = field(default_factory=list)
    deleted: List[IaCFileResult] = field(default_factory=list)


@dataclass
class IaCDiffScanResult(Base):
    id: str = ""
    type: str = ""
    iac_engine_version: str = ""
    entities_with_incidents: IaCDiffScanEntities = field(
        default_factory=IaCDiffScanEntities
    )


IaCDiffScanResultSchema = marshmallow_dataclass.class_schema(
    IaCDiffScanResult, BaseSchema
)


def mock_api_iac_diff_scan(
    client: Any,
    reference: bytes,
    current: bytes,
    scan_parameters: IaCScanParameters,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Union[Detail, IaCDiffScanResult]:
    scan = client.iac_directory_scan(
        Path("."),
        [],
        scan_parameters,
        extra_headers,
    )
    result = IaCDiffScanResult(
        scan.id,
        scan.type,
        scan.iac_engine_version,
        entities_with_incidents=IaCDiffScanEntities([], [], []),
    )
    result.status_code = 200
    return result
