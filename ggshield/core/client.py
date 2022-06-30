from typing import Dict, Optional, Union, cast

import click
import requests
import urllib3
from pygitguardian import GGClient
from pygitguardian.client import is_ok
from pygitguardian.models import Detail
from requests import Response, Session

from ..iac.models import IaCScanResult, IaCScanResultSchema
from ..iac.models.iac_scan_parameters import IaCScanParameters, IaCScanParametersSchema
from .config import Config
from .config.errors import UnknownInstanceError
from .constants import DEFAULT_DASHBOARD_URL


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
        if "detail" not in data:
            data = {"detail": str(data)}
    else:
        data = {"detail": resp.text}

    return cast(Detail, Detail.SCHEMA.load(data))


def create_client_from_config(config: Config) -> GGClient:
    """
    Create a GGClient using parameters from Config.
    """
    try:
        api_key = config.api_key
        api_url = config.api_url
    except UnknownInstanceError as e:
        if e.instance == DEFAULT_DASHBOARD_URL:
            # This can happen when the user first tries the app and has not gone through
            # the authentication procedure yet. In this case, replace the error message
            # complaining about an unknown instance with a more user-friendly one.
            raise click.ClickException("GitGuardian API key is needed.")
        else:
            raise

    return create_client(api_key, api_url, allow_self_signed=config.allow_self_signed)


def create_client(
    api_key: str, api_url: str, *, allow_self_signed: bool = False
) -> GGClient:
    """
    Implementation of create_client_from_config(). Exposed as a function for specific
    cases such as needing a GGClient instance while defining the config account.
    """
    session = create_session(allow_self_signed=allow_self_signed)
    try:
        return IaCGGClient(
            api_key=api_key,
            base_uri=api_url,
            user_agent="ggshield",
            timeout=60,
            session=session,
        )
    except ValueError as e:
        # Can be raised by pygitguardian
        raise click.ClickException(f"Failed to create API client. {e}")


def create_session(allow_self_signed: bool = False) -> Session:
    session = Session()
    if allow_self_signed:
        urllib3.disable_warnings()
        session.verify = False
    return session


class IaCGGClient(GGClient):
    def directory_scan(
        self,
        directory: bytes,
        scan_parameters: IaCScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, IaCScanResult]:

        result: Union[Detail, IaCScanResult]
        try:
            resp = self.request(
                "post",
                endpoint="iac_scan",
                extra_headers=extra_headers,
                files={
                    "directory": directory,
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
                result = IaCScanResultSchema().load(resp.json())
            else:
                result = load_detail(resp)

            result.status_code = resp.status_code

        return result
