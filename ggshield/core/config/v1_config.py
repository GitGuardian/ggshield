from typing import Any, Dict, List, Optional, Union

from ggshield.core.url_utils import api_to_dashboard_url


def convert_v1_config_dict(
    data: Dict[str, Any], deprecation_messages: List[str]
) -> Dict[str, Any]:
    """
    Takes a dict representing a v1 .gitguardian.yaml and returns a v2 dict.
    Appends any deprecation message to `deprecation_messages`.
    """

    # If data contains the old "api-url" key, turn it into an "instance" key,
    # but only if there is no "instance" key
    try:
        api_url = data.pop("api_url")
    except KeyError:
        pass
    else:
        if "instance" not in data:
            data["instance"] = api_to_dashboard_url(api_url, warn=True)

    if "all_policies" in data:
        deprecation_messages.append(
            "The `all_policies` option has been deprecated and is now ignored."
        )

    if "ignore_default_excludes" in data:
        deprecation_messages.append(
            "The `ignore_default_exclude` option has been deprecated and is now ignored."
        )

    secret_dct = {}
    if matches_ignore := data.get("matches_ignore"):
        secret_dct["ignored_matches"] = [
            _convert_matches_ignore_entry(x) for x in matches_ignore
        ]

    def copy_if_set(dct: Dict[str, Any], dst_key: str, src_key: Optional[str] = None):
        """Helper function: if `src_key` exists in `data`, copies its value to
        `dct[dst_key]`.
        If `src_key` is None, use `dst_key` as the source key.
        """
        if src_key is None:
            src_key = dst_key
        try:
            value = data[src_key]
        except KeyError:
            return
        dct[dst_key] = value

    copy_if_set(secret_dct, "show_secrets")
    copy_if_set(secret_dct, "ignored_detectors", "banlisted_detectors")
    copy_if_set(secret_dct, "ignored_paths", "paths_ignore")

    dct = {
        "secret": secret_dct,
    }
    copy_if_set(dct, "instance")
    copy_if_set(dct, "exit_zero")
    copy_if_set(dct, "verbose")
    copy_if_set(dct, "insecure", "allow_self_signed")
    copy_if_set(dct, "max_commits_for_hook")

    return dct


def _convert_matches_ignore_entry(entry: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    v1 config format allowed to use just a hash of the secret for matches_ignore
    field v2 does not. This function converts the hash-only entry.
    """
    if isinstance(entry, str):
        return {"name": "", "match": entry}
    else:
        return entry
