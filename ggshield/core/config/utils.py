import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Union

import click
import yaml
from appdirs import user_config_dir
from pydantic import BaseModel, Extra

from ggshield.core.constants import AUTH_CONFIG_FILENAME


def replace_in_keys(data: Union[List, Dict], old_char: str, new_char: str) -> None:
    """Replace old_char with new_char in data keys."""
    if isinstance(data, dict):
        for key, value in list(data.items()):
            replace_in_keys(value, old_char=old_char, new_char=new_char)
            if old_char in key:
                new_key = key.replace(old_char, new_char)
                data[new_key] = data.pop(key)
    elif isinstance(data, list):
        for element in data:
            replace_in_keys(element, old_char=old_char, new_char=new_char)


def load_yaml(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None

    with open(path, "r") as f:
        try:
            data = yaml.safe_load(f) or {}
        except Exception as e:
            message = f"Parsing error while reading {path}:\n{str(e)}"
            click.echo(message)
            return None
        else:
            replace_in_keys(data, old_char="-", new_char="_")
            return data


def save_yaml(data: Dict[str, Any], path: str) -> None:
    replace_in_keys(data, "_", "-")
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        try:
            stream = yaml.dump(data, indent=2, default_flow_style=False)
            f.write(stream)
        except Exception as e:
            raise click.ClickException(
                f"Error while saving config in {path}:\n{str(e)}"
            ) from e


def get_auth_config_dir() -> str:
    return user_config_dir(appname="ggshield", appauthor="GitGuardian")


def get_auth_config_filepath() -> str:
    return os.path.join(get_auth_config_dir(), AUTH_CONFIG_FILENAME)


def get_global_path(filename: str) -> str:
    return os.path.join(os.path.expanduser("~"), filename)


class ConfigBaseModel(BaseModel):
    class Config:
        extra = Extra.forbid

    def update_from_model(self, other: BaseModel) -> None:
        """
        Update `self` with fields from `other` if they are set.
        `self` and `other` are expected to be the same type.
        """
        assert self.__class__ is other.__class__
        for name in other.__fields_set__:
            value = other.__dict__[name]
            if isinstance(value, list):
                self.__dict__[name].extend(value)
            elif isinstance(value, set):
                self.__dict__[name].update(value)
            elif isinstance(value, BaseModel):
                self.__dict__[name].update_from_model(value)
            else:
                self.__dict__[name] = value


def ensure_path_exists(dir_path: str) -> None:
    Path(dir_path).mkdir(parents=True, exist_ok=True)


def get_attr_mapping(
    classes: Iterable[Tuple[Type[ConfigBaseModel], str]]
) -> Dict[str, str]:
    """
    Return a mapping from a field name to the correct class
    raise an AssertionError if there is a field name collision
    """
    mapping = {}
    for klass, attr_name in classes:
        for field_name in klass.__fields__.keys():
            assert field_name not in mapping, f"Conflict with field '{field_name}'"
            mapping[field_name] = attr_name
    return mapping
