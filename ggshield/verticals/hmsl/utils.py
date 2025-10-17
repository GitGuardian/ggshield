import logging
import re
import time
from typing import Optional

import jwt
from pygitguardian.models import Detail, JWTService

from ggshield.core.client import create_client
from ggshield.core.config.config import Config
from ggshield.core.dirs import get_cache_dir
from ggshield.core.errors import (
    AuthExpiredError,
    MissingTokenError,
    UnknownInstanceError,
)
from ggshield.verticals.hmsl.client import HMSLClient


logger = logging.getLogger(__name__)


# Tools for parsing env files
ENV_LINE_REGEX = re.compile(r'(\S+)(?: *?)=(?: *?)((?:".*?[^\\]")|\S+)')

EXCLUDED_KEYS = {
    "HOST",
    "HOSTNAME",
    "PATH",
    "PORT",
}

EXCLUDED_VALUES = {
    "0",
    "1",
    "disabled",
    "enabled",
    "false",
    "n",
    "no",
    "none",
    "null",
    "off",
    "on",
    "true",
    "y",
    "yes",
}


def get_client(config: Config, hmsl_command_path: str) -> HMSLClient:
    """
    Get an instance of HMSLClient according to your current CLI config and the
    current CLI command.
    """
    token = get_token(config)
    return HMSLClient(
        url=config.hmsl_url, hmsl_command_path=hmsl_command_path, jwt=token
    )


def get_token_path():
    return get_cache_dir() / "hmsl_token"


def get_token(config: Config) -> Optional[str]:
    """Get a JWT token to use the HMSL service.
    If we are not logged, no token is returned and
    the client uses the HMSL service anonymously.
    """

    # Look for a stored token
    token = load_token_from_disk()

    if is_token_valid(token, config.hmsl_audience):
        logger.debug("Using cached HMSL token")
        return token

    logger.debug("No valid token cached. Getting a new one.")

    try:
        client = create_client(
            api_url=config.saas_api_url,
            api_key=config.saas_api_key,
            allow_self_signed=config.user_config.insecure,
        )
        audience = config.hmsl_audience
    except (MissingTokenError, AuthExpiredError):
        logger.debug("No API key found, using HMSL anonymously.")
        return None
    except UnknownInstanceError as e:
        logger.warning(f"Unknown instance {e.instance}, using HMSL anonymously.")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error: {e}. Using HMSL anonymously.")
        return None

    # Get a new token
    logger.debug("Requesting new JWT token")
    response = client.create_jwt(audience, JWTService.HMSL)
    if isinstance(response, Detail):
        logger.warning(f"Unexpected error: {response.detail}. Using HMSL anonymously.")
        return None
    token = response.token

    # Cache it for future calls and return it
    save_token(token)
    return token


def is_token_valid(token: Optional[str], audience: str) -> bool:
    if not token:
        return False
    try:
        # We only check expiration at this point.
        decoded = jwt.decode(
            token, options={"verify_signature": False, "require": ["exp", "aud"]}
        )
        # If we changed the target audience (only useful during tests)
        if decoded["aud"] != audience:
            return False
        # Keep one minute of leeway
        return int(decoded["exp"]) > time.time() + 60
    except Exception:
        pass
    return False


def load_token_from_disk() -> Optional[str]:
    try:
        return get_token_path().read_text()
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning(f"Error while loading token: {e}")
    return None


def save_token(token: str) -> None:
    try:
        get_token_path().write_text(token)
    except Exception as e:
        logger.warning(f"Error while saving token: {e}")


def remove_token_from_disk() -> None:
    try:
        get_token_path().unlink(missing_ok=True)
    except OSError:
        pass
    except Exception as e:
        logger.warning(f"Error while removing token: {e}")
