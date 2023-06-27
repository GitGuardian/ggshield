from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Literal, Optional, Union, cast

import marshmallow_dataclass
from pygitguardian.client import GGClient, is_ok, load_detail
from pygitguardian.models import Base, BaseSchema, Detail, FromDictMixin


@dataclass
class ComputeSCAFilesResult(Base, FromDictMixin):
    sca_files: List[str]
    potential_siblings: List[str]


ComputeSCAFilesResult.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(ComputeSCAFilesResult, base_schema=BaseSchema)(),
)

@dataclass
class ExposedVulnerability(Base, FromDictMixin):
    cve_ids: List[str]
    severity: str
    created_at: datetime | None
    fixed_version: str | None
    summary: str

@dataclass
class PackageVulnerability(Base, FromDictMixin):
    package_full_name: str
    version: str
    ecosystem: str
    dependency_type: Literal["direct", "transitive"] | None
    vulns: List[ExposedVulnerability]


@dataclass
class LocationOutput(Base, FromDictMixin):
    location: str
    package_vulns: List[PackageVulnerability]

@dataclass
class SCAScanDiffResult(Base, FromDictMixin):
    scanned_files: List[str]
    added_vulns: List[LocationOutput]
    removed_vulns: List[LocationOutput]


class SCAClient:
    def __init__(self, client: GGClient):
        self._client = client

    def compute_sca_files(
        self,
        touched_files: List[str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, ComputeSCAFilesResult]:
        response = self._client.post(
            endpoint="sca/compute_sca_files/",
            data={"touched_files": touched_files},
            extra_headers=extra_headers,
        )
        result: Union[Detail, ComputeSCAFilesResult]
        if is_ok(response):
            result = ComputeSCAFilesResult.from_dict(response.json())
        else:
            result = load_detail(response)

        result.status_code = response.status_code
        return result

    def scan_diff(
        self,
        reference: bytes,
        current: bytes,
    ) -> SCAScanDiffResult:
        response = self._client.post(
            endpoint="sca/sca_scan_diff/",
            data={"reference": reference, "current": current},
            extra_headers=extra_headers,
        )
        return response
