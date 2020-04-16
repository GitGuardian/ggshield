from typing import Dict, List, Union

import os
import json
import requests


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
    FILE_PATH = "scanning-api/scan/file"
    FILES_PATH = "scanning-api/scan/files"
    REPO_PATH = "repo-analyzer/user/{}/repo/{}"

    def __init__(self, token: str) -> None:
        self.token = token
        self.base_url = os.getenv(
            "GITGUARDIAN_API_URL", "https://api.gitguardian.com/api/v1/"
        )
        self.blacklist = []

    @property
    def headers(self) -> Dict:
        return {
            "Authorization": "token {}".format(self.token),
            "Content-Type": "application/json",
        }

    def scan_file(self, content: str) -> Dict:
        """ Scan a content string. """
        payload = {"content": content, "detectors_banlist": self.blacklist}
        path = self.base_url + self.FILE_PATH
        return self.get(path, headers=self.headers, data=json.dumps(payload))

    def scan_files(self, files: List) -> Dict:
        """ Scan multiple files at once. """
        payload = {"files": files, "detectors_banlist": self.blacklist}
        path = self.base_url + self.FILES_PATH
        return self.post(path, headers=self.headers, data=json.dumps(payload))

    def scan_repo(
        self, user: str, repo: str, gh_access_token: Union[str, None] = None
    ) -> Dict:
        """
        Scan a GitHub repository.

        :param user: GitHub username
        :param repo: GitHub repository name
        :param gh_access_token: GitHub Access Token (for private repo)
        :param check: Check the secret
        :raise: PublicScanningException
        """
        path = self.base_url + self.REPO_PATH.format(user, repo)
        return self.get(path, headers=self.headers)

    def _request(self, method, path, headers=None, data=None, params=None):
        response = getattr(requests, method)(
            self.base_url + path, headers=self.headers, data=data, params=params
        )
        try:
            body = response.json()
        except json.decoder.JSONDecodeError:
            raise PublicScanningException(
                "JSON parsing failed ({})".format(response.text)
            )
        if not response.ok:
            raise PUBLIC_SCANNING_EXCEPTIONS.get(
                response.status_code, PublicScanningException
            )(body.get("detail") or body.get("message") or body.get("reason"))

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

    def create_token(self, name="") -> Dict:
        """
        Create a token for the current user
        """
        return self.post("/tokens/", data=json.dumps({"name": name}))

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
