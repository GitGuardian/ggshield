from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union

import marshmallow_dataclass
from pygitguardian import GGClient
from pygitguardian.iac_models import IaCFileResult, IaCScanParameters
from pygitguardian.models import Base, BaseSchema, Detail

from ggshield.core.client import create_session
from ggshield.core.config.config import Config
from ggshield.core.constants import DEFAULT_INSTANCE_URL
from ggshield.core.errors import APIKeyCheckError, UnexpectedError, UnknownInstanceError


# TODO: move these dataclasses into pygitguardian


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


class MockClient(GGClient):
    # TODO: move this into GGClient
    def mock_api_iac_diff_scan(
        self,
        reference: bytes,
        current: bytes,
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCDiffScanResult]:
        scan = self.iac_directory_scan(
            Path("."),
            [],
            scan_parameters,
            extra_headers,
        )
        if isinstance(scan, Detail):
            return scan
        result = IaCDiffScanResult(
            scan.id,
            scan.type,
            scan.iac_engine_version,
            entities_with_incidents=IaCDiffScanEntities([], [], []),
        )
        result.status_code = 200
        return result


# TODO: remove this once api_iac_diff_scan is moved into GGClient
def create_mock_client_from_config(config: Config) -> MockClient:
    try:
        api_key = config.api_key
        api_url = config.api_url
    except UnknownInstanceError as e:
        if e.instance == DEFAULT_INSTANCE_URL:
            raise APIKeyCheckError(
                e.instance,
                "",
            )
        else:
            raise

    session = create_session(allow_self_signed=config.allow_self_signed)
    try:
        return MockClient(
            api_key=api_key,
            base_uri=api_url,
            user_agent="ggshield",
            timeout=60,
            session=session,
        )
    except ValueError as e:
        raise UnexpectedError(f"Failed to create API client. {e}")
