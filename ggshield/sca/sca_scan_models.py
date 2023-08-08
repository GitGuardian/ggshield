from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, cast

import marshmallow_dataclass
from pygitguardian.models import Base, BaseSchema, FromDictMixin
from typing_extensions import Literal

from ggshield.core.config.user_config import SCAIgnoredVulnerability


@dataclass
class SCAScanParameters(Base, FromDictMixin):
    minimum_severity: Optional[str] = None
    ignored_vulnerabilities: List[SCAIgnoredVulnerability] = field(default_factory=list)


SCAScanParameters.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(SCAScanParameters, base_schema=BaseSchema)(),
)


@dataclass
class ComputeSCAFilesResult(Base, FromDictMixin):
    sca_files: List[str]
    potential_siblings: List[str]


ComputeSCAFilesResult.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(ComputeSCAFilesResult, base_schema=BaseSchema)(),
)


@dataclass
class SCAVulnerability(Base, FromDictMixin):
    severity: str
    summary: str
    # TODO Remove Optional clause when identifier field is in production on backend side
    identifier: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    fixed_version: Optional[str] = None


SCAVulnerability.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(SCAVulnerability, base_schema=BaseSchema)(),
)

SCADependencyType = Literal["direct", "transitive"]


@dataclass
class SCAVulnerablePackageVersion(Base, FromDictMixin):
    package_full_name: str
    version: str
    ecosystem: str
    dependency_type: Optional[SCADependencyType] = None
    vulns: List[SCAVulnerability] = field(default_factory=list)


SCAVulnerablePackageVersion.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(
        SCAVulnerablePackageVersion, base_schema=BaseSchema
    )(),
)


@dataclass
class SCALocationVulnerability(Base, FromDictMixin):
    location: str
    package_vulns: List[SCAVulnerablePackageVersion] = field(default_factory=list)


SCALocationVulnerability.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(
        SCALocationVulnerability, base_schema=BaseSchema
    )(),
)


@dataclass
class SCAScanAllOutput(Base, FromDictMixin):
    scanned_files: List[str] = field(default_factory=list)
    found_package_vulns: List[SCALocationVulnerability] = field(default_factory=list)


SCAScanAllOutput.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(SCAScanAllOutput, base_schema=BaseSchema)(),
)


@dataclass
class SCAScanDiffOutput(Base, FromDictMixin):
    scanned_files: List[str] = field(default_factory=list)
    added_vulns: List[SCALocationVulnerability] = field(default_factory=list)
    removed_vulns: List[SCALocationVulnerability] = field(default_factory=list)


SCAScanDiffOutput.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(SCAScanDiffOutput, base_schema=BaseSchema)(),
)
