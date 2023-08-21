import json
import logging
import subprocess


logger = logging.getLogger(__name__)


class VaultCliTokenFetchingError(Exception):
    """Raised when the token used by Vault CLI cannot be fetched."""

    pass


def get_vault_cli_token() -> str:
    """Get the Vault token used by Vault CLI."""

    try:
        result = subprocess.run(
            ["vault", "token", "lookup", "--format=json"],
            capture_output=True,
            text=True,
            check=True,
        )
        json_content = json.loads(result.stdout)
        return json_content["data"]["id"]
    except subprocess.CalledProcessError as exc:
        msg = "error when calling Vault CLI."
        if exc.returncode == 127:
            msg = "Vault CLI not found. Are you sure it is installed and in your PATH?"
        raise VaultCliTokenFetchingError(msg) from exc
    except Exception as exc:
        msg = "error getting token from Vault CLI."
        raise VaultCliTokenFetchingError(msg) from exc
