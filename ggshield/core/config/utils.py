from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Set, Union, overload

import yaml
import yaml.parser
import yaml.scanner

from ggshield.core.constants import (
    AUTH_CONFIG_FILENAME,
    DEFAULT_CONFIG_FILENAME,
    USER_CONFIG_FILENAMES,
)
from ggshield.core.dirs import get_config_dir, get_project_root_dir, get_user_home_dir
from ggshield.core.errors import UnexpectedError
from ggshield.utils.git_shell import GitExecutableNotFound


def replace_dash_in_keys(data: Union[List[Any], Dict[str, Any]]) -> Set[str]:
    """Replace '-' with '_' in data keys.

    If a key exists in both dash and underscore versions, then only the underscore
    version is kept.

    Returns a set with the names of the renamed/removed dash keys."""
    dash_keys = set()

    if isinstance(data, dict):
        for key, value in list(data.items()):
            dash_keys.update(replace_dash_in_keys(value))
            if "-" in key:
                dash_value = data.pop(key)
                # If an underscore-version of the key exist, do not replace it
                new_key = key.replace("-", "_")
                if new_key not in data:
                    data[new_key] = dash_value
                dash_keys.add(key)
    elif isinstance(data, list):
        for element in data:
            dash_keys.update(replace_dash_in_keys(element))

    return dash_keys


def load_yaml_dict(path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        return None

    with path.open() as f:
        try:
            data = yaml.safe_load(f) or {}
        except (yaml.parser.ParserError, yaml.scanner.ScannerError) as e:
            message = f"{path} is not a valid YAML file:\n{str(e)}"
            raise ValueError(message)

    if not isinstance(data, dict):
        raise ValueError(f"{path} should be a dictionary.")

    return data


def save_yaml_dict(
    data: Dict[str, Any], path: Union[str, Path], restricted: bool = False
) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w") as f:
        try:
            if restricted:
                # Restrict file permissions: read and write for owner only (600)
                p.chmod(0o600)

            stream = yaml.dump(data, indent=2, default_flow_style=False)
            f.write(stream)

        except Exception as e:
            raise UnexpectedError(f"Failed to save config to {path}:\n{str(e)}") from e


def get_auth_config_filepath() -> Path:
    return get_config_dir() / AUTH_CONFIG_FILENAME


def get_global_path(filename: str) -> Path:
    return get_user_home_dir() / filename


@overload
def find_global_config_path(*, to_write: Literal[False] = False) -> Optional[Path]: ...


@overload
def find_global_config_path(*, to_write: Literal[True]) -> Path: ...


def find_global_config_path(*, to_write: bool = False) -> Optional[Path]:
    """
    Returns the path to the user global config file (the file in the user home
    directory).
    If there is no such file:
    - If `to_write` is False, returns None.
    - If `to_write` is True, returns the path to the default file.

    This means the function never returns None if `to_write` is True.
    """
    for filename in USER_CONFIG_FILENAMES:
        path = get_global_path(filename)
        if path.exists():
            return path
    return get_global_path(DEFAULT_CONFIG_FILENAME) if to_write else None


def find_local_config_path() -> Optional[Path]:
    try:
        project_root_dir = get_project_root_dir(Path())
    except GitExecutableNotFound:
        project_root_dir = Path()
    for filename in USER_CONFIG_FILENAMES:
        path = project_root_dir / filename
        if path.exists():
            return path
    return None


def update_dict_from_other(dct: Dict[str, Any], other: Dict[str, Any]) -> None:
    """
    Merge values from `other` dict into `dct`. List entries are appended, sets are
    updated, dicts are merged.

    The merge happens in-place: `dct` is modified.
    """
    for key, value in other.items():
        try:
            if value is None:
                continue
            if isinstance(value, list):
                dct.setdefault(key, []).extend(value)
            elif isinstance(value, set):
                dct.setdefault(key, set()).update(value)
            elif isinstance(value, dict):
                update_dict_from_other(dct.setdefault(key, {}), value)
            else:
                dct[key] = value
        except AttributeError:
            raise UnexpectedError(f"Failed to load configuration on key '{key}'")


def remove_common_dict_items(
    dct: Dict[str, Any], reference_dct: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Returns a copy of `dct` with all items already in `reference_dct` removed.
    """

    result_dct = dict()
    for key, value in dct.items():
        reference_value = reference_dct[key]

        if isinstance(value, dict):
            value = remove_common_dict_items(value, reference_value)
            # Remove empty dicts
            if not value:
                continue
        else:
            if value == reference_value:
                continue

        result_dct[key] = value

    return result_dct


def remove_url_trailing_slash(url: str) -> str:
    if url[-1] == "/":
        return url[:-1]
    else:
        return url
