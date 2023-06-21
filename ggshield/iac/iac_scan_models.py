import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

import marshmallow_dataclass
import requests
from pygitguardian import GGClient
from pygitguardian.iac_models import (
    IaCFileResult,
    IaCScanParameters,
    IaCScanParametersSchema,
)
from pygitguardian.models import Base, BaseSchema, Detail
from requests import Response

from ggshield.core.client import create_session
from ggshield.core.config.config import Config
from ggshield.core.constants import DEFAULT_INSTANCE_URL
from ggshield.core.errors import APIKeyCheckError, UnexpectedError, UnknownInstanceError


# TODO: move these dataclasses into pygitguardian
DEFAULT_API_VERSION = "v1"


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

logger = logging.getLogger(__name__)


class MockClient(GGClient):
    def mock_post(
        self,
        endpoint: str,
        json: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        return self.mock_request(
            "post",
            endpoint=endpoint,
            json=json,
            extra_headers=extra_headers,
            **kwargs,
        )

    def mock_request(
        self,
        method: str,
        endpoint: str,
        version: Optional[str] = DEFAULT_API_VERSION,
        extra_headers: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> Response:
        url = self._url_from_endpoint(endpoint, version)

        headers = (
            {**self.session.headers, **extra_headers}
            if extra_headers
            else self.session.headers
        )
        start = time.time()
        response: Response = self.session.request(
            method=method, url=url, timeout=self.timeout, headers=headers, **kwargs
        )
        duration = time.time() - start
        logger.debug(
            "method=%s endpoint=%s status_code=%s duration=%f",
            method,
            endpoint,
            response.status_code,
            duration,
        )

        self.app_version: Optional[str] = response.headers.get(
            "X-App-Version", self.app_version
        )
        self.secrets_engine_version: Optional[str] = response.headers.get(
            "X-Secrets-Engine-Version", self.secrets_engine_version
        )

        return response

    # TODO: move this into GGClient
    def mock_api_iac_diff_scan(
        self,
        reference: bytes,
        current: bytes,
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCDiffScanResult]:
        result: Union[Detail, IaCDiffScanResult]

        try:
            resp = self.mock_post(
                endpoint="iac_diff_scan",
                extra_headers=extra_headers,
                files={
                    "reference": reference,
                    "current": current,
                },
                data={
                    "scan_parameters": IaCScanParametersSchema().dumps(scan_parameters),
                },
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            result = IaCDiffScanResultSchema().load(resp.json())
            result.status_code = resp.status_code

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
