import copy
import json
import os
from typing import Any, Dict, List

import click
from pygitguardian.models import PolicyBreak

from ggshield.config import Attribute
from ggshield.filter import get_ignore_sha


class Cache:
    last_found_secrets: List

    CACHE_FILENAME = "./.cache_ggshield"
    attributes: List[Attribute] = [
        Attribute("last_found_secrets", list()),
    ]

    def __init__(self) -> None:
        self.purge()
        self.load_cache()

    def __getattr__(self, name: str) -> Any:
        # Required for dynamic types on mypy
        return object.__getattribute__(self, name)

    def get_attributes_keys(self) -> List:
        return list(
            list(zip(*self.attributes))[0]
        )  # get list of first elements in tuple

    def __setattr__(self, name: str, value: Any) -> None:
        if isinstance(value, list):
            attribute = getattr(self, name)

            if isinstance(attribute, list):
                for elem in value:
                    if elem not in attribute:
                        attribute.append(elem)
            else:
                getattr(self, name).update(value)
        else:
            super().__setattr__(name, value)

    def load_cache(self) -> bool:
        if not os.path.isfile(self.CACHE_FILENAME):
            return True

        _cache: dict = {}
        if os.stat(self.CACHE_FILENAME).st_size != 0:
            try:
                f = open(self.CACHE_FILENAME, "r")
            except PermissionError:
                # Hotfix: for the time being we skip cache handling if permission denied
                return True
            else:
                with f:
                    try:
                        _cache = json.load(f)
                        # Convert back all sets that were serialized as lists
                        for attr in self.attributes:
                            if type(attr.default) is set and attr.name in _cache:
                                _cache[attr.name] = set(_cache[attr.name]) or set()
                    except Exception as e:
                        raise click.ClickException(
                            "Parsing error while"
                            f"reading {self.CACHE_FILENAME}:\n{str(e)}"
                        )
        self.update_cache(**_cache)
        return True

    def update_cache(self, **kwargs: Any) -> None:
        for key, item in kwargs.items():
            if key in self.get_attributes_keys():
                if isinstance(item, list):
                    attr = getattr(self, key)
                    for elem in item:
                        if elem not in attr:
                            attr.append(elem)
                else:
                    setattr(self, key, item)

                setattr(self, key, item)
            else:
                click.echo("Unrecognized key in cache: {}".format(key))

    def to_dict(self) -> Dict[str, Any]:
        _cache = {key: getattr(self, key) for key in self.get_attributes_keys()}
        # Convert all sets into list so they can be json serialized
        for key in self.get_attributes_keys():
            value = _cache[key]
            if type(value) is set:
                _cache[key] = list(value)
        return _cache

    def save(self) -> bool:
        if not self.last_found_secrets:
            # if there are no found secrets, don't modify the cache file
            return True

        try:
            f = open(self.CACHE_FILENAME, "w")
        except OSError:
            # Hotfix: for the time being we skip cache handling if permission denied
            return True
        else:
            with f:
                try:
                    json.dump(self.to_dict(), f)

                except Exception as e:
                    raise click.ClickException(
                        f"Error while saving cache in {self.CACHE_FILENAME}:\n{str(e)}"
                    )
        return True

    def purge(self) -> None:
        for attr in self.attributes:
            # Deep copy to avoid mutating the default value
            default = copy.copy(attr.default)
            super().__setattr__(attr.name, default)

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
