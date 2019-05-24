import os
import aiohttp
from typing import Dict, Union, List

import requests


class ScanningApiClient:
    URL = "https://scanning.api.dev.gitguardian.com/v2/scan/file"
    TIMEOUT = 10

    def __init__(
        self, apikey: str = "", url: str = URL, timeout: int = TIMEOUT
    ) -> None:
        self.apikey = apikey
        self.url = url
        self.timeout = timeout

    @property
    def headers(self) -> Dict:
        return {"apikey": self.apikey}

    async def scan_file(
        self, content: str, filename: str = None, check: Union[bool, None] = None
    ) -> Dict:
        """
        Calls Scanning API and returns response
        """
        payload = {"content": content}
        if filename:
            payload["filename"] = filename
        if isinstance(check, bool):
            payload["check"] = check

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.url, headers=self.headers, json=payload, timeout=self.timeout
            ) as resp:
                response = await resp.json()

                if resp.status >= 400:
                    error = (
                        response["message"]
                        or response["msg"]
                        or "An unknown error occured"
                    )

                    raise Exception(error)

                return response


class PublicScanningException(Exception):
    pass


class PublicScanningBadRequest(PublicScanningException):
    pass


class PublicScanningUnauthorized(PublicScanningException):
    pass


class PublicScanningForbidden(PublicScanningException):
    pass


class PublicScanningNotFound(PublicScanningException):
    pass


class PublicScanningServerError(PublicScanningException):
    pass


PUBLIC_SCANNING_EXCEPTIONS = {
    400: PublicScanningBadRequest,
    401: PublicScanningUnauthorized,
    403: PublicScanningForbidden,
    404: PublicScanningNotFound,
    500: PublicScanningServerError,
}


class PublicScanningApiClient:
    URL = os.getenv("PUBLIC_SCANNING_API_URL")

    def __init__(self, token: str) -> None:
        self.token = token

    @property
    def headers(self) -> Dict:
        return {
            "Authorization": "token {}".format(self.token),
            "Content-Type": "application/json",
        }

    def _request(self, method, path, headers=None, data=None, params=None):
        response = getattr(requests, method)(
            self.URL + path, headers=self.headers, data=data, params=params
        )
        try:
            body = response.json()
        except Exception:
            print(response.text)
            return
        if not response.ok:
            raise PUBLIC_SCANNING_EXCEPTIONS.get(
                response.status_code, PublicScanningException
            )(body.get("detail", None))

        return body

    def get(self, path, **kwargs):
        return self._request("get", path, **kwargs)

    def post(self, path, **kwargs):
        return self._request("post", path, **kwargs)

    def put(self, path, **kwargs):
        return self._request("post", path, **kwargs)

    def delete(self, path, **kwargs):
        return self._request("delete", path, **kwargs)

    # Manage API tokens
    def list_tokens(self) -> List:
        """
        List all the token of the current user
        """
        return self.get("/tokens/")

    def retrieve_token(self, token_id: str) -> Dict:
        """
        Retrieve a token of the current user via its id
        """
        return self.get("/tokens/{}/".format(token_id))

    def create_token(self) -> Dict:
        """
        Create a token for the current user
        """
        return self.post("/tokens/")

    def delete_token(self, token_id: str) -> Dict:
        """
        Delete a token of the current user via its id
        """
        return self.delete("/tokens/{}/".format(token_id))

    # Quotas
    def quotas(self):
        """
        List the quota status of the current user
        """
        return self.get("/quotas/")
