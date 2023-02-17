import logging
import os.path
import time
from typing import Optional, Tuple

import requests

from ggshield import __version__
from ggshield.core.dirs import get_cache_dir

from .config.utils import load_config_data, save_yaml_dict


logger = logging.getLogger(__name__)
CACHE_FILE = os.path.join(
    get_cache_dir(),
    "update_check.yaml",
)


# Use a short timeout to prevent blocking
CHECK_TIMEOUT = 5


def _split_version(version: str) -> Tuple[int, ...]:
    return tuple([int(x) for x in version.split(".")])


def check_for_updates() -> Optional[str]:
    """
    Check for ggshield updates on GitHub. Return the latest version if available.
    Query GitHub API at most once per day and save locally the latest version in a file.
    """
    check_at = -1.0
    # Load the last time we checked
    try:
        cached_data = load_config_data(CACHE_FILE)
    except ValueError:
        # Swallow the error
        cached_data = None
    if cached_data is not None:
        try:
            check_at = cached_data["check_at"]
        except Exception as e:
            logger.warning("Could not load cached latest version: %s", e)

    if check_at > 0 and (time.time() - check_at < 24 * 60 * 60):
        # We checked today, no need to check again
        return None

    logger.debug("Checking the latest released version of ggshield...")

    # Save check time now so that it is saved even if the check fails. This ensures we
    # don't try for every command if the user does not have network access.
    try:
        save_yaml_dict({"check_at": time.time()}, CACHE_FILE)
    except Exception as e:
        logger.warning("Could not save time of version check to cache: %s", e)
        # Do not continue if we can't save check time. If we continue we are going to
        # send requests to api.github.com every time ggshield is called.
        return None

    try:
        resp = requests.get(
            "https://api.github.com/repos/GitGuardian/GGShield/releases/latest",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": f"GGShield {__version__}",
                "X-Github-Api-Version": "2022-11-28",
            },
            timeout=CHECK_TIMEOUT,
        )
    except Exception as e:
        logger.warning("Failed to connect to api.github.com: %s", e)
        return None

    if resp.status_code != 200:
        # Handle GitHub rate limit responses gracefully
        # https://docs.github.com/en/rest/overview/resources-in-the-rest-api?apiVersion=2022-11-28#rate-limiting
        if int(resp.headers.get("X-RateLimit-Remaining", -1)) == 0:
            logger.warning("GitHub rate limit exceeded - rescheduling update check")

            # Reset the next update check based on when the GH API quota resets
            check_at = int(resp.headers.get("X-RateLimit-Reset", -1)) - 24 * 60 * 60
            if check_at < 0:
                # Somehow we've hit the rate limit and the reset header is missing
                # This can only happen if GH changes their responses
                logger.warning("Failed rescheduling update check")
                return None

            try:
                save_yaml_dict({"check_at": check_at}, CACHE_FILE)
            except Exception as e:
                logger.warning("Could not save time of version check to cache: %s", e)

            return None

        logger.warning("Failed to check: %s", resp.text)
        return None

    try:
        data = resp.json()
        latest_version: str = data["tag_name"][1:]

        current_version_split = _split_version(__version__)
        latest_version_split = _split_version(latest_version)
    except Exception as e:
        logger.warning("Failed to parse response: %s", e)
        return None

    if current_version_split < latest_version_split:
        return latest_version
    return None
