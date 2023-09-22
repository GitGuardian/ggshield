import logging
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from ggshield.core.text_utils import display_error
from ggshield.utils.git_shell import get_git_root, is_git_dir
from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)


def _find_dot_env() -> Optional[Path]:
    """Look for a .env to load, returns its path if found"""
    if env_var := os.getenv("GITGUARDIAN_DOTENV_PATH"):
        path = Path(env_var)
        if not path.is_file():
            display_error("GITGUARDIAN_DOTENV_PATH does not point to a valid .env file")
            return None

        return path

    # Look for a .env in the current directory
    env = Path(".env")
    if env.is_file():
        return env

    # If we are in a git checkout, look for a .env at the root of the checkout
    if is_git_dir(os.getcwd()):
        env = get_git_root() / ".env"
        if env.is_file():
            return env

    return None


def load_dot_env() -> None:
    """Loads .env file into os.environ."""
    dont_load_env = getenv_bool("GITGUARDIAN_DONT_LOAD_ENV")
    if dont_load_env:
        logger.debug("Not loading .env, GITGUARDIAN_DONT_LOAD_ENV is set")
        return

    dot_env_path = _find_dot_env()
    if dot_env_path:
        dot_env_path = dot_env_path.absolute()
        logger.debug("Loading environment file %s", dot_env_path)
        load_dotenv(dot_env_path, override=True)
