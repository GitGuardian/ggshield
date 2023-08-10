from dataclasses import dataclass
from typing import Dict, Optional, Set


@dataclass
class PreparedSecrets:
    payload: Set[str]
    mapping: Dict[str, str]


@dataclass
class SecretWithKey:
    key: Optional[str]
    value: str
