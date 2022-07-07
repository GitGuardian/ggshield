import copy
import os
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, Union

import click
import yaml
from appdirs import user_config_dir

from ggshield.core.constants import AUTH_CONFIG_FILENAME
from ggshield.core.text_utils import display_error


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


def load_yaml(path: str, raise_exc: bool = False) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None

    with open(path, "r") as f:
        try:
            data = yaml.safe_load(f) or {}
        except Exception as e:
            message = f"Parsing error while reading {path}:\n{str(e)}"
            if raise_exc:
                raise click.ClickException(message) from e
            else:
                display_error(message)
                return None
        else:
            replace_in_keys(data, old_char="-", new_char="_")
            return data


def custom_asdict(obj: Any, root: bool = False) -> Union[List, Dict]:
    """
    customization of dataclasses.asdict to allow implementing a "to_dict"
    method for customization.
    root=True skips the first to_dict, to allow calling this function from "to_dict"
    """
    if is_dataclass(obj):
        if not root and hasattr(obj, "to_dict"):
            return obj.to_dict()  # type: ignore
        result = {}
        for f in fields(obj):
            result[f.name] = custom_asdict(getattr(obj, f.name))
        return result
    elif isinstance(obj, (list, tuple)):
        return type(obj)(custom_asdict(v) for v in obj)  # type: ignore
    elif isinstance(obj, dict):
        return type(obj)((k, custom_asdict(v)) for k, v in obj.items())
    elif isinstance(obj, set):
        # Turn sets into lists so that YAML serialization does not turn them into YAML
        # unordered sets
        return [custom_asdict(v) for v in obj]
    else:
        return copy.deepcopy(obj)  # type: ignore


def get_auth_config_dir() -> str:
    return user_config_dir(appname="ggshield", appauthor="GitGuardian")


def get_auth_config_filepath() -> str:
    return os.path.join(get_auth_config_dir(), AUTH_CONFIG_FILENAME)


def get_global_path(filename: str) -> str:
    return os.path.join(os.path.expanduser("~"), filename)


class YAMLFileConfig:
    """Helper class to define configuration object loaded from a YAML file"""

    def __init__(self, **kwargs: Any) -> None:
        raise NotImplementedError

    def to_dict(self) -> Union[List, Dict]:
        return custom_asdict(self, root=True)

    def update_config(self, data: Dict[str, Any]) -> bool:
        """
        Update the current config, ignoring the unrecognized keys
        """
        field_names = {field_.name for field_ in fields(self)}
        for key, item in data.items():
            if key not in field_names:
                click.echo("Unrecognized key in config: {}".format(key))
                continue
            if isinstance(getattr(self, key), list):
                getattr(self, key).extend(item)
            elif isinstance(getattr(self, key), set):
                getattr(self, key).update(item)
            else:
                setattr(self, key, item)
        return True

    def save_yaml(self, path: str) -> None:
        data = self.to_dict()
        replace_in_keys(data, old_char="_", new_char="-")
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


def ensure_path_exists(dir_path: str) -> None:
    Path(dir_path).mkdir(parents=True, exist_ok=True)


def get_attr_mapping(
    classes: Iterable[Tuple[Type[YAMLFileConfig], str]]
) -> Dict[str, str]:
    """
    Return a mapping from a field name to the correct class
    raise an AssertionError if there is a field name collision
    """
    mapping = {}
    for klass, attr_name in classes:
        for field_ in fields(klass):
            assert field_.name not in mapping, f"Conflict with field '{field_.name}'"
            mapping[field_.name] = attr_name
    return mapping
