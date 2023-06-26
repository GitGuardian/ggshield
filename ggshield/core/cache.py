import json
import os
from typing import Any, Dict, List

from pygitguardian.models import PolicyBreak

from ggshield.core.constants import CACHE_FILENAME
from ggshield.core.errors import UnexpectedError
from ggshield.core.filter import get_ignore_sha
from ggshield.core.text_utils import display_warning
from ggshield.core.types import IgnoredMatch


SECRETS_CACHE_KEY = "last_found_secrets"


class Cache:
    def __init__(self, cache_filename: str = CACHE_FILENAME) -> None:
        self.cache_filename = cache_filename
        self.last_found_secrets: List[IgnoredMatch] = []
        self.purge()
        self.load_cache()

    def load_cache(self) -> bool:
        if not os.path.isfile(self.cache_filename):
            return True

        _cache: dict = {}
        if os.stat(self.cache_filename).st_size != 0:
            try:
                f = open(self.cache_filename)
            except PermissionError:
                # Hotfix: for the time being we skip cache handling if permission denied
                return True
            with f:
                try:
                    _cache = json.load(f)
                except Exception as e:
                    raise UnexpectedError(
                        f"Parsing error while reading {self.cache_filename}:\n{str(e)}"
                    )
        self.update_cache(**_cache)
        return True

    def update_cache(self, **kwargs: Any) -> None:
        if SECRETS_CACHE_KEY in kwargs:
            self.last_found_secrets = [
                IgnoredMatch.from_dict(secret)
                for secret in kwargs.pop(SECRETS_CACHE_KEY)
            ]
        if kwargs:
            for key in kwargs.keys():
                display_warning(f'Unrecognized key in cache "{key}"')

    def to_dict(self) -> Dict[str, Any]:
        return {
            SECRETS_CACHE_KEY: [secret.to_dict() for secret in self.last_found_secrets]
        }

    def save(self) -> None:
        if not self.last_found_secrets:
            # if there are no found secrets, don't modify the cache file
            return
        try:
            f = open(self.cache_filename, "w")
        except OSError:
            # Hotfix: for the time being we skip cache handling if permission denied
            return
        with f:
            try:
                json.dump(self.to_dict(), f)
            except Exception as e:
                raise UnexpectedError(
                    f"Failed to save cache in {self.cache_filename}:\n{str(e)}"
                )

    def purge(self) -> None:
        self.last_found_secrets = []

    def add_found_policy_break(self, policy_break: PolicyBreak, filename: str) -> None:
        if policy_break.is_secret:
            ignore_sha = get_ignore_sha(policy_break)
            if not any(
                last_found.match == ignore_sha for last_found in self.last_found_secrets
            ):
                self.last_found_secrets.append(
                    IgnoredMatch(
                        name=f"{policy_break.break_type} - {filename}",
                        match=get_ignore_sha(policy_break),
                    )
                )


class ReadOnlyCache(Cache):
    """
    A version of Cache which does not write anything to the disk.
    """

    def save(self) -> None:  # pragma: no cover
        return None
