import logging
import os.path
import time
from typing import Optional, Tuple

import appdirs
import requests

from ggshield import __version__

from .config.utils import load_yaml, save_yaml


logger = logging.getLogger(__name__)
CACHE_FILE = os.path.join(appdirs.user_cache_dir(), "ggshield", "update_check.yaml")


def _split_version(version: str) -> Tuple[int, ...]:
    return tuple([int(x) for x in version.split(".")])


def check_for_updates() -> Optional[str]:
    """
    Check for ggshield updates on GitHub. Return the latest version if available.
    Query GitHub API at most once per day and save locally the latest version in a file.
    """
    check_at = -1.0
    # Load the last time we checked
    cached_data = load_yaml(CACHE_FILE)
    if cached_data is not None:
        try:
            check_at = cached_data["check_at"]
        except Exception as e:
            logger.warning("Could not load cached latest version: %s", e)

    if check_at > 0 and (time.time() - check_at < 24 * 60 * 60):
        # We checked today, no need to check again
        return None

    logger.debug("Checking the latest released version of ggshield...")
    resp = requests.get(
        "https://api.github.com/repos/GitGuardian/GGShield/releases/latest"
    )
    if resp.status_code != 200:
        logger.error("Failed to check: %s", resp.text)
        return None

    try:
        data = resp.json()
        latest_version: str = data["tag_name"][1:]
    except (requests.exceptions.JSONDecodeError, AttributeError, TypeError):
        logger.error("Failed to parse response: %s", resp.text)
        return None

    # Cache the time of the check
    save_yaml({"check_at": time.time()}, CACHE_FILE)

    current_version_split = _split_version(__version__)
    latest_version_split = _split_version(latest_version)
    if current_version_split < latest_version_split:
        return latest_version
    return None
