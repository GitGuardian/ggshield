from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class VaultMount:
    """
    Model to represent a Vault mount.
    """

    name: str


@dataclass
class VaultKvMount(VaultMount):
    """
    Model to represent a Vault KV mount.
    """

    version: str


@dataclass
class VaultSecrets:
    """
    Model to hold secrets fetched from the vault.

    The aim is to include the secrets themselves and the not_fetched_paths
    list to communicate the paths that could not be fetched
    (permission denied, errors etc.).
    """

    secrets: List[Tuple[str, str]]
    not_fetched_paths: List[str]
