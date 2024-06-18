import logging
from typing import Any, Dict, Generator, List, Tuple
from urllib.parse import urlparse

import requests

from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultForbiddenItemError,
    VaultInvalidUrlError,
    VaultNotFoundItemError,
    VaultPathIsNotADirectoryError,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultSecrets,
)


logger = logging.getLogger(__name__)


class VaultAPIClient:
    """Client to interact with Vault API."""

    def __init__(self, vault_url: str, api_token: str) -> None:
        self.session = requests.Session()
        self.session.headers["X-Vault-Token"] = api_token

        if not vault_url.startswith("http://") and not vault_url.startswith("https://"):
            vault_url = f"https://{vault_url}"
        try:
            self.vault_url = urlparse(vault_url).geturl()
        except ValueError:
            raise VaultInvalidUrlError(
                f"cannot parse the Vault URL '{vault_url}'. Are you sure it is valid?"
            )

    def _make_request(
        self, endpoint: str, method: str = "GET", api_version: str = "v1"
    ) -> Dict[str, Any]:
        """ "
        Make request to the API.
        """
        api_res = self.session.request(
            method, f"{self.vault_url}/{api_version}/{endpoint}"
        )
        api_res.raise_for_status()

        return api_res.json()

    def get_kv_mounts(self) -> Generator[VaultKvMount, None, None]:
        """
        Get all kv mounts for the Vault instance.

        Will try the /sys/mounts endpoint first, and if there is a forbidden error
        fallback to the /sys/internal/ui internal endpoint.
        """

        try:
            api_res = self._make_request("sys/mounts")["data"]
        except requests.HTTPError:
            api_res = self._make_request("sys/internal/ui/mounts")["data"]["secret"]

        for key, value in api_res.items():
            if value["type"] != "kv":
                continue

            yield VaultKvMount(
                name=key.rstrip("/"),  # remove trailing slash
                version=value["options"]["version"],
            )

    def list_kv_items(self, mount: VaultKvMount, path: str) -> List[str]:
        logger.debug(f"Listing kv items for mount {mount.name} at {path}")

        api_endpoint = (
            f"{mount.name}/metadata/{path}"
            if mount.version == "2"
            else f"{mount.name}/{path}"
        )

        try:
            api_res = self._make_request(api_endpoint, method="LIST")
        except requests.HTTPError as exc:
            if exc.response.status_code == 403:
                raise VaultForbiddenItemError(
                    f"cannot access item on mount {mount.name} at path {path}"
                )

            # The API return 404 when trying to list items when the path is a file
            # and not a directory
            if exc.response.status_code == 404:
                raise VaultPathIsNotADirectoryError()

            raise exc

        return [item.rstrip("/") for item in api_res["data"]["keys"]]

    def get_kv_secrets(self, mount: VaultKvMount, path: str) -> List[Tuple[str, str]]:
        """
        Get secrets from the specified mount at the specified path.

        Returns a list of tuples containing secret key and secret value
        """

        logger.debug(f"Getting secrets at {path}")
        api_endpoint = (
            f"{mount.name}/data/{path}"
            if mount.version == "2"
            else f"{mount.name}/{path}"
        )
        try:
            api_res = self._make_request(api_endpoint)
        except requests.HTTPError as exc:
            if exc.response.status_code == 403:
                raise VaultForbiddenItemError(
                    f"cannot access item on mount {mount.name} at path {path}"
                )

            if exc.response.status_code == 404:
                raise VaultNotFoundItemError(
                    f"{path} was not found: it's either not a file, "
                    "was deleted or cannot be accessed with the current token"
                )

            raise exc

        data = api_res["data"]["data"] if mount.version == "2" else api_res["data"]
        return [
            (f"{path}/{secret_name}", secret_value)
            for secret_name, secret_value in data.items()
        ]

    def _get_secrets_or_empty(
        self, mount: VaultKvMount, folder_path: str
    ) -> VaultSecrets:
        """
        Call get_kv_secrets on the given mount and folder path.

        Return the secrets or an empty list if VaultNotFoundItemError was raised.
        """
        try:
            return VaultSecrets(
                secrets=self.get_kv_secrets(mount, folder_path),
                not_fetched_paths=[],
            )
        except VaultNotFoundItemError as exc:
            logger.debug(f"Not found error: {exc}")
            return VaultSecrets(secrets=[], not_fetched_paths=[folder_path])
        except VaultForbiddenItemError as exc:
            logger.debug(f"Forbidden error: {exc}")
            return VaultSecrets(secrets=[], not_fetched_paths=[folder_path])

    def _get_secrets_from_path(
        self, mount: VaultKvMount, folder_path: str, recursive: bool
    ) -> VaultSecrets:
        """
        Get the secrets on the given mount and folder path.
        If recursive is True, iterate recursively on subfolders.

        Return the secrets or an empty list if errors were raised.
        """
        # Get current directory secret
        try:
            subfolders = self.list_kv_items(mount, folder_path)
        except VaultPathIsNotADirectoryError:
            return self._get_secrets_or_empty(mount, folder_path)
        except VaultForbiddenItemError as exc:
            logger.debug(f"Forbidden error: {exc}")
            return VaultSecrets(secrets=[], not_fetched_paths=[folder_path])

        if not recursive:
            return VaultSecrets(secrets=[], not_fetched_paths=[])

        result = VaultSecrets(secrets=[], not_fetched_paths=[])
        for subfolder in subfolders:
            subfolder_result = self._get_secrets_from_path(
                mount, f"{folder_path}/{subfolder}", True
            )
            result.secrets += subfolder_result.secrets
            result.not_fetched_paths += subfolder_result.not_fetched_paths

        return result

    def get_secrets(
        self, mount: VaultKvMount, path: str, recursive: bool
    ) -> VaultSecrets:
        # Check first if it's a directory
        try:
            keys = self.list_kv_items(mount, path)
        except VaultPathIsNotADirectoryError:
            # If it's a file, return directly
            return self._get_secrets_or_empty(mount, path)

        # If it's a folder, get secrets of the folder
        result = VaultSecrets(secrets=[], not_fetched_paths=[])
        for folder in keys:
            folder_path = f"{path}/{folder}".strip("/")
            folder_result = self._get_secrets_from_path(mount, folder_path, recursive)
            result.secrets += folder_result.secrets
            result.not_fetched_paths += folder_result.not_fetched_paths

        return result
