import urllib.parse
from typing import Any, Optional, Tuple, Union

import requests
from marshmallow import Schema
from requests import Response, Session, codes

from .models import Detail, ScanResult
from .schemas import DetailSchema, DocumentSchema, ScanResultSchema


_BASE_URI = "https://api.gitguardian.com"
_API_VERSION = "v1"
_DEFAULT_TIMEOUT = 20.0  # 20s default timeout


class GGClient:
    DETAIL_SCHEMA = DetailSchema()
    DOCUMENT_SCHEMA = DocumentSchema()
    SCAN_RESULT_SCHEMA = ScanResultSchema()

    def __init__(
        self,
        token: str,
        base_uri: str = None,
        session: requests.Session = None,
        user_agent: str = "",
        timeout: float = _DEFAULT_TIMEOUT,
    ):
        """
        :param token: APIKey to be added to requests
        :type token: str
        :param base_uri: Base URI for the API, defaults to "https://api.gitguardian.com"
        :type base_uri: str, optional
        :param session: custom requests session, defaults to requests.Session()
        :type session: requests.Session, optional
        :param user_agent: user agent to identify requests, defaults to ""
        :type user_agent: str, optional
        :param timeout: request timeout, defaults to 20s
        :type timeout: float, optional

        :raises ValueError: if the protocol is invalid
        """

        if base_uri:
            if not base_uri.startswith(("http://", "https://")):
                raise ValueError("Invalid protocol, prepend with http:// or https://")
        else:
            base_uri = _BASE_URI

        if not isinstance(token, str):
            raise TypeError("Missing token string")

        self.base_uri = base_uri
        self.token = token
        self.session = (
            session if session is isinstance(session, Session) else requests.Session()
        )
        self.timeout = timeout

        self.session.headers.update(
            {
                "User-Agent": " ".join(["pygitguardian", user_agent]),
                "Authorization": "Token {0}".format(token),
            }
        )

    def request(
        self,
        method: str,
        endpoint: str,
        schema: Schema = None,
        version: str = _API_VERSION,
        **kwargs
    ) -> Tuple[Any, Response]:
        if version:
            endpoint = urllib.parse.urljoin(version + "/", endpoint)

        url = urllib.parse.urljoin(self.base_uri, endpoint)

        response = self.session.request(
            method=method, url=url, timeout=self.timeout, **kwargs
        )

        if response.headers["content-type"] != "application/json":
            raise TypeError("Response is not JSON")

        if response.status_code == codes.ok and schema:
            obj = schema.load(response.json())
        else:
            obj = self.DETAIL_SCHEMA.load(response.json())

        obj.status_code = response.status_code

        return obj, response

    def post(
        self,
        endpoint: str,
        data: str = None,
        schema: Schema = None,
        version: str = _API_VERSION,
        **kwargs
    ) -> Tuple[Any, Response]:
        return self.request(
            "post",
            endpoint=endpoint,
            schema=schema,
            json=data,
            version=version,
            **kwargs,
        )

    def get(
        self,
        endpoint: str,
        schema: Schema = None,
        version: str = _API_VERSION,
        **kwargs
    ) -> Tuple[Any, Response]:
        return self.request(
            method="get", endpoint=endpoint, schema=schema, version=version, **kwargs
        )

    def content_scan(
        self, document: str, filename: Optional[str] = None
    ) -> Union[Detail, ScanResult]:
        """content_scan handles the /scan endpoint of the API

        use filename=dummy to avoid evalutation of filename and file extension policies

        :param filename: name of file, example: "intro.py"
        :type filename: str
        :param document: content of file
        :type document: str
        :return: Detail or ScanResult response
        :rtype: Union[Detail, ScanResult]
        """

        doc_dict = {"document": document}
        if filename:
            doc_dict["filename"] = filename

        request_obj = self.DOCUMENT_SCHEMA.load(doc_dict)
        obj, _ = self.post(
            endpoint="scan", data=request_obj, schema=self.SCAN_RESULT_SCHEMA
        )
        return obj

    def health_check(self) -> Detail:
        """health_check handles the /health endpoint of the API

        use Detail.status_code to check the response status code of the API

        200 if server is online and token is valid
        :return: Detail response,
        :rtype: Detail
        """
        obj, _ = self.get(endpoint="health")
        return obj
