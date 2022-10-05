import json
import logging
import os.path
import time
from typing import Optional

import appdirs
import requests

from ggshield import __version__

from .config.utils import load_yaml, save_yaml


logger = logging.getLogger(__name__)
CACHE_FILE = os.path.join(appdirs.user_cache_dir(), "ggshield_release.yaml")


def check_for_updates() -> Optional[str]:
    """
    Check for ggshield updates on GitHub. Return the latest version if available.
    Query GitHub API at most once per day and save locally the latest version in a file.
    """
    latest_version: Optional[str] = None
    check_at = -1.0
    # Try to load the cached latest version
    try:
        cached_data = load_yaml(CACHE_FILE)
        if isinstance(cached_data, dict):
            latest_version = cached_data["latest_version"]
            check_at = cached_data["check_at"]
    except (FileNotFoundError, json.JSONDecodeError, AttributeError) as e:
        logger.debug(f"Could not load cached latest version: {e}")

    # Check for a new version at most once per day
    if (
        latest_version is None
        or check_at < 0
        or (time.time() - check_at > 24 * 60 * 60)
    ):
        logger.debug("Checking the latest released version of ggshield...")
        resp = requests.get(
            "https://api.github.com/repos/GitGuardian/GGShield/releases/latest"
        )
        if resp.status_code == 200:
            try:
                data = resp.json()
                latest_version = data["tag_name"][1:]
                check_at = time.time()
            except (requests.exceptions.JSONDecodeError, AttributeError, TypeError):
                pass

            # Cache locally the latest version
            save_yaml(
                {"latest_version": latest_version, "check_at": check_at}, CACHE_FILE
            )

    if latest_version is not None:
        current_version_split = tuple(map(int, __version__.split(".")))
        latest_version_split = tuple(map(int, latest_version.split(".")))
        if current_version_split < latest_version_split:
            return latest_version
    return None
