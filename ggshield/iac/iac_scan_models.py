import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, cast

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


# TODO: this file contains elements that are or should be part of pygitguardian

DEFAULT_API_VERSION = "v1"


# TODO: move this dataclass into pygitguardian
@dataclass
class IaCDiffScanEntities(Base):
    unchanged: List[IaCFileResult] = field(default_factory=list)
    new: List[IaCFileResult] = field(default_factory=list)
    deleted: List[IaCFileResult] = field(default_factory=list)


# TODO: move this dataclass into pygitguardian
@dataclass
class IaCDiffScanResult(Base):
    id: str = ""
    type: str = ""
    iac_engine_version: str = ""
    entities_with_incidents: IaCDiffScanEntities = field(
        default_factory=IaCDiffScanEntities
    )


# TODO: move this schema into pygitguardian
IaCDiffScanResultSchema = marshmallow_dataclass.class_schema(
    IaCDiffScanResult, BaseSchema
)

logger = logging.getLogger(__name__)


# TODO: Delete this after moving iac_diff_scan into pygitguardian
def is_ok(resp: Response) -> bool:
    """
    is_ok returns True is the API responded with 200
    and the content type is JSON.
    """
    return (
        resp.headers["content-type"] == "application/json" and resp.status_code == 200
    )


# TODO: Delete this after moving iac_diff_scan into pygitguardian
def load_detail(resp: Response) -> Detail:
    """
    load_detail loads a Detail from a response
    be it JSON or html.

    :param resp: API response
    :type resp: Response
    :return: detail object of response
    :rtype: Detail
    """
    if resp.headers["content-type"] == "application/json":
        data = resp.json()
    else:
        data = {"detail": resp.text}

    return cast(Detail, Detail.SCHEMA.load(data))


# TODO: delete this class after updating pygitguardian
class TmpGGClient(GGClient):
    """Temporary class used until iac_diff_scan can be moved to Ggclient."""

    # TODO: Move this method into GGClient.
    def iac_diff_scan(
        self,
        reference: bytes,
        current: bytes,
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCDiffScanResult]:
        result: Union[Detail, IaCDiffScanResult]
        try:
            resp = self.post(
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
            if is_ok(resp):
                # IaCDiffScanResultSchema.from_dict(resp.json()) does not work for now
                # TODO: replace load with from_dict once this is moved into pygitguardian
                result = IaCDiffScanResultSchema().load(resp.json())  # type: ignore
            else:
                result = load_detail(resp)

            result.status_code = resp.status_code
        return result


# TODO: remove this once iac_diff_scan is moved into GGClient
def create_mock_client_from_config(config: Config) -> TmpGGClient:
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
        return TmpGGClient(
            api_key=api_key,
            base_uri=api_url,
            user_agent="ggshield",
            timeout=60,
            session=session,
        )
    except ValueError as e:
        raise UnexpectedError(f"Failed to create API client. {e}")
