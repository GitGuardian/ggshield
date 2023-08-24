import logging
import os
from datetime import datetime
from itertools import islice
from typing import Iterable, List, Optional, TypeVar

from dotenv import load_dotenv

from ggshield.utils.git_shell import get_git_root, is_git_dir

from .text_utils import display_error


logger = logging.getLogger(__name__)


def _find_dot_env() -> Optional[str]:
    """Look for a .env to load, returns its path if found"""
    env = os.getenv("GITGUARDIAN_DOTENV_PATH")
    if env:
        if os.path.isfile(env):
            return env
        else:
            display_error("GITGUARDIAN_DOTENV_PATH does not point to a valid .env file")
            return None

    # Look for a .env in the current directory
    env = ".env"
    if os.path.isfile(env):
        return env

    # If we are in a git checkout, look for a .env at the root of the checkout
    if is_git_dir(os.getcwd()):
        env = os.path.join(get_git_root(), ".env")
        if os.path.isfile(env):
            return env

    return None


def load_dot_env() -> None:
    """Loads .env file into os.environ."""
    dont_load_env = os.getenv("GITGUARDIAN_DONT_LOAD_ENV", False)
    if dont_load_env:
        logger.debug("Not loading .env, GITGUARDIAN_DONT_LOAD_ENV is set")
        return

    dot_env_path = _find_dot_env()
    if dot_env_path:
        dot_env_path = os.path.abspath(dot_env_path)
        logger.debug("Loading environment file %s", dot_env_path)
        load_dotenv(dot_env_path, override=True)


def datetime_from_isoformat(text: str) -> datetime:
    """Work around for datetime.isoformat() not supporting ISO dates ending with Z"""
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


T = TypeVar("T")


def batched(iterable: Iterable[T], batch_size: int) -> Iterable[List[T]]:
    it = iter(iterable)
    while True:
        batch = list(islice(it, batch_size))
        if batch:
            yield batch
        else:
            return
