import logging
import os
from pathlib import Path
from typing import Optional, Set

from dotenv import dotenv_values, load_dotenv

from ggshield.core import ui
from ggshield.utils.git_shell import get_git_root, is_git_available, is_git_dir
from ggshield.utils.os import getenv_bool


TRACKED_ENV_VARS = {
    "GITGUARDIAN_INSTANCE",
    "GITGUARDIAN_API_URL",
    "GITGUARDIAN_API_KEY",
}

logger = logging.getLogger(__name__)


def _find_dot_env() -> Optional[Path]:
    """Look for a .env to load, returns its path if found"""
    if env_var := os.getenv("GITGUARDIAN_DOTENV_PATH"):
        path = Path(env_var)
        if not path.is_file():
            ui.display_error(
                "GITGUARDIAN_DOTENV_PATH does not point to a valid .env file"
            )
            return None

        return path

    # Look for a .env in the current directory
    env = Path(".env")
    if env.is_file():
        return env

    # If we are in a git checkout, look for a .env at the root of the checkout
    if is_git_available() and is_git_dir(os.getcwd()):
        env = get_git_root() / ".env"
        if env.is_file():
            return env

    return None


def load_dot_env() -> Set[str]:
    """
    Loads .env file into os.environ.
    Return the list of env vars that were set by the dotenv file
    among env vars in TRACKED_ENV_VARS
    """
    dont_load_env = getenv_bool("GITGUARDIAN_DONT_LOAD_ENV")
    if dont_load_env:
        logger.debug("Not loading .env, GITGUARDIAN_DONT_LOAD_ENV is set")
        return set()

    dot_env_path = _find_dot_env()
    if dot_env_path:
        dot_env_path = dot_env_path.absolute()
        logger.debug("Loading environment file %s", dot_env_path)
        load_dotenv(dot_env_path, override=True)

    return dotenv_values(dot_env_path).keys() & TRACKED_ENV_VARS
