import platform
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

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
        base_uri: Optional[str] = None,
        session: Optional[requests.Session] = None,
        user_agent: Optional[str] = None,
        timeout: Optional[float] = _DEFAULT_TIMEOUT,
    ) -> "GGClient":
        """
        :param token: APIKey to be added to requests
        :param base_uri: Base URI for the API, defaults to "https://api.gitguardian.com"
        :param session: custom requests session, defaults to requests.Session()
        :param user_agent: user agent to identify requests, defaults to ""
        :param timeout: request timeout, defaults to 20s

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
        self.user_agent = "pygitguardian/{0} ({1};py{2})".format(
            "1.0.3", platform.system(), platform.python_version()
        )

        if user_agent:
            self.user_agent = " ".join([self.user_agent, user_agent])

        self.session.headers.update(
            {"User-Agent": self.user_agent, "Authorization": "Token {0}".format(token)}
        )

    def request(
        self,
        method: str,
        endpoint: str,
        schema: Schema = None,
        version: str = _API_VERSION,
        many: bool = False,
        **kwargs,
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
            obj = schema.load(response.json(), many=many)
            if many:
                for element in obj:
                    element.status_code = response.status_code
            else:
                obj.status_code = response.status_code
        else:
            obj = self.DETAIL_SCHEMA.load(response.json(), many=many)
            obj.status_code = response.status_code

        return obj, response

    def post(
        self,
        endpoint: str,
        data: str = None,
        schema: Schema = None,
        version: str = _API_VERSION,
        many: bool = False,
        **kwargs,
    ) -> Tuple[Any, Response]:
        return self.request(
            "post",
            endpoint=endpoint,
            schema=schema,
            json=data,
            version=version,
            many=many,
            **kwargs,
        )

    def get(
        self,
        endpoint: str,
        schema: Schema = None,
        version: str = _API_VERSION,
        many: bool = False,
        **kwargs,
    ) -> Tuple[Any, Response]:
        return self.request(
            method="get", endpoint=endpoint, schema=schema, version=version, **kwargs
        )

    def content_scan(
        self, document: str, filename: Optional[str] = None
    ) -> Tuple[Union[Detail, ScanResult], int]:
        """
        content_scan handles the /scan endpoint of the API

        :param filename: name of file, example: "intro.py"
        :param document: content of file
        :return: Detail or ScanResult response and status code
        """

        doc_dict = {"document": document}
        if filename:
            doc_dict["filename"] = filename

        request_obj = self.DOCUMENT_SCHEMA.load(doc_dict)
        obj, resp = self.post(
            endpoint="scan", data=request_obj, schema=self.SCAN_RESULT_SCHEMA
        )
        return obj, resp.status_code

    def multi_content_scan(
        self, documents: Iterable[Dict[str, str]],
    ) -> Tuple[Union[Detail, List[ScanResult]], int]:
        """
        multi_content_scan handles the /multiscan endpoint of the API

        :param documents: List of dictionaries containing the keys document
        and, optionaly, filename.
            example: [{"document":"example content","filename":"intro.py"}]
        :return: Detail or ScanResult response and status code
        """

        if all(isinstance(doc, dict) for doc in documents):
            request_obj = self.DOCUMENT_SCHEMA.load(documents, many=True)
        else:
            raise TypeError("documents must be a dict")

        obj, resp = self.post(
            endpoint="multiscan",
            data=request_obj,
            schema=self.SCAN_RESULT_SCHEMA,
            many=True,
        )
        return obj, resp.status_code

    def health_check(self) -> Tuple[Detail, int]:
        """
        health_check handles the /health endpoint of the API

        use Detail.status_code to check the response status code of the API

        200 if server is online and token is valid
        :return: Detail response and status code
        """
        obj, resp = self.get(endpoint="health")
        return obj, resp.status_code
