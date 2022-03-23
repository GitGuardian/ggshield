import json
import os
from typing import Any, Dict

import click
from pygitguardian.models import PolicyBreak

from ggshield.constants import CACHE_FILENAME
from ggshield.filter import get_ignore_sha


class Cache:
    def __init__(self, cache_filename: str = CACHE_FILENAME) -> None:
        self.cache_filename = cache_filename
        self.purge()
        self.load_cache()

    def load_cache(self):
        if not os.path.isfile(self.cache_filename):
            return

        _cache: dict = {}
        if os.stat(self.cache_filename).st_size != 0:
            try:
                f = open(self.cache_filename, "r")
            except PermissionError:
                # Hotfix: for the time being we skip cache handling if permission denied
                return
            with f:
                try:
                    _cache = json.load(f)
                except Exception as e:
                    raise click.ClickException(
                        "Parsing error while"
                        f"reading {self.cache_filename}:\n{str(e)}"
                    )
        self.update_cache(**_cache)
        return True

    def update_cache(self, **kwargs):
        if "last_found_secrets" in kwargs:
            self.last_found_secrets = kwargs.pop("last_found_secrets")
        if kwargs:
            for key in kwargs.keys():
                click.echo(f'Unrecognized key in cache "{key}"')

    def to_dict(self) -> Dict[str, Any]:
        return {"last_found_secrets": self.last_found_secrets}

    def save(self):
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
                raise click.ClickException(
                    f"Error while saving cache in {self.cache_filename}:\n{str(e)}"
                )

    def purge(self) -> None:
        self.last_found_secrets = []

    def add_found_policy_break(self, policy_break: PolicyBreak, filename: str) -> None:
        if policy_break.is_secret:
            ignore_sha = get_ignore_sha(policy_break)
            if not any(
                last_found["match"] == ignore_sha
                for last_found in self.last_found_secrets
            ):
                self.last_found_secrets.append(
                    {
                        "name": f"{policy_break.break_type} - {filename}",
                        "match": get_ignore_sha(policy_break),
                    }
                )
