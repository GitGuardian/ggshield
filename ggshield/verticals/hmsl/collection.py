from dataclasses import dataclass
from enum import Enum, auto
from typing import (
    Callable,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    TextIO,
    Tuple,
)

from dotenv import dotenv_values

from ggshield.core.filter import censor_string
from ggshield.verticals.hmsl import PREFIX_LENGTH
from ggshield.verticals.hmsl.crypto import hash_string
from ggshield.verticals.hmsl.utils import EXCLUDED_KEYS, EXCLUDED_VALUES


class InputType(Enum):
    FILE = auto()
    ENV = auto()


@dataclass
class PreparedSecrets:
    payload: Set[str]
    mapping: Dict[str, str]


@dataclass
class SecretWithKey:
    key: Optional[str]
    value: str


# Methods to compute names for secrets
# They are useful to help the user identify the secret that may leaked
# with a more "human-readable" string than a hash.
# Takes the secret and optional key as input and returns a string.

NamingStrategy = Callable[[SecretWithKey], str]
NAMING_STRATEGIES: Dict[str, NamingStrategy] = {
    "censored": lambda secret: censor_string(secret.value),
    "cleartext": lambda secret: secret.value,
    "none": lambda _: "",
    "key": lambda secret: secret.key or censor_string(secret.value),
}


def collect_list(input: List[Tuple[str, str]]) -> Iterator[SecretWithKey]:
    """
    Collect the secrets to pass to prepare.

    Input should be a list of tuple with the first item of the tuple being the secret
    key and the second the secret value.
    """
    for key, value in input:
        # filter our excluded keys and values
        if not key or not value:
            continue
        if (
            key.split("/")[-1].upper() in EXCLUDED_KEYS  # Only use the variable name
            or value.lower() in EXCLUDED_VALUES
        ):
            continue
        yield SecretWithKey(key=key, value=value)


def collect(
    input: TextIO, input_type: InputType = InputType.FILE
) -> Iterator[SecretWithKey]:
    """
    Collect the secrets to pass to prepare.
    """
    if input_type == InputType.ENV:
        config = dotenv_values(stream=input)
        for key, value in config.items():
            # filter our excluded keys and values
            if not key or not value:
                continue
            if key.upper() in EXCLUDED_KEYS or value.lower() in EXCLUDED_VALUES:
                continue
            yield SecretWithKey(value=value, key=key)
    else:
        for line in input:
            secret = line.strip()
            if secret == "":
                # Skip empty lines
                continue
            yield SecretWithKey(value=secret, key=None)


def prepare(
    secrets: Iterable[SecretWithKey],
    naming_strategy: NamingStrategy,
    *,
    full_hashes: bool = False,
) -> PreparedSecrets:
    """
    Prepare the secrets so they can later be checked.
    """
    hashes: Set[str] = set()
    mapping: Dict[str, str] = {}
    for secret in secrets:
        name = naming_strategy(secret)
        hash = hash_string(secret.value)
        mapping[hash] = name
        if full_hashes:
            hashes.add(hash)
        else:
            hashes.add(hash[:PREFIX_LENGTH])
    return PreparedSecrets(
        payload=hashes,
        mapping=mapping,
    )
