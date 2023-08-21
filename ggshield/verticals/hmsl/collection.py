from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Dict, Iterable, Iterator, Optional, Set, TextIO

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


def collect(
    input: TextIO, input_type: InputType = InputType.FILE
) -> Iterator[SecretWithKey]:
    """
    Collect the secrets
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
