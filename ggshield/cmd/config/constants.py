from dataclasses import dataclass


DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


@dataclass
class ConfigField:
    """Meta-information about a config field, used by `ggshield config` commands to
    manipulate configuration files.
    """

    # The name of the field in the config file.
    name: str

    # True if this field is stored in auth_config.yaml, False if it's in the global
    # user config file.
    auth_config: bool = False

    # True if this field can be set for an individual instance. Only valid for
    # auth_config fields.
    per_instance_ok: bool = False


# All editable config fields
_FIELDS = (
    ConfigField(
        "instance",
    ),
    ConfigField(
        "default_token_lifetime",
        auth_config=True,
        per_instance_ok=True,
    ),
)

FIELDS = {x.name: x for x in _FIELDS}

FIELD_NAMES = sorted(FIELDS.keys())

FIELD_NAMES_DOC = "Supported keys:\n" + "\n".join(f"- `{x}`" for x in FIELD_NAMES)
