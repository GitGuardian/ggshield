import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Union, cast

import requests

from ggshield import __version__
from ggshield.utils.itertools import batched

from .crypto import decrypt, make_hint


PREFIX_LENGTH = 5
HASHES_BATCH_SIZE = 100
PREFIXES_BATCH_SIZE = 10
HASH_REGEX = re.compile(r"^[0-9a-f]{64}$")
PREFIX_REGEX = re.compile(f"^[0-9a-f]{{{PREFIX_LENGTH}}}$")


@dataclass
class Secret:
    hash: str
    count: int
    url: Union[str, None] = None


@dataclass
class Match:
    hint: str
    payload: str

    def decrypt(self, hash: str) -> Secret:
        key = bytes.fromhex(hash)
        payload = base64.b64decode(self.payload)
        decrypted = json.loads(decrypt(payload, key))
        if decrypted.get("l"):
            url = decrypted.get("l", {}).get("u")
        else:
            url = None
        return Secret(
            hash=hash,
            count=decrypted["c"],
            url=url,
        )


@dataclass
class SecretsResponse:
    secrets: List[Secret]


@dataclass
class PrefixesResponse:
    matches: List[Match]


@dataclass
class Quota:
    remaining: int
    limit: int
    reset: datetime


class HMSLClient:
    def __init__(
        self,
        url: str,
        hmsl_command_path: str,
        jwt: Optional[str] = None,
        *,
        prefix_length: int = PREFIX_LENGTH,
    ) -> None:
        self.url = url.strip("/")
        self.jwt = jwt
        self.prefix_length = prefix_length
        self._quota: Optional[Quota] = None

        # Create a session with common headers.
        self.session = requests.Session()
        self.session.headers["GGShield-HMSL-Command-Name"] = hmsl_command_path.replace(
            "ggshield ", ""
        ).replace(" ", "_")
        self.session.headers["User-Agent"] = f"GGShield {__version__}"

    @property
    def quota(self) -> Quota:
        """Return the remaining credits."""
        if self._quota is None:
            # Use the side effect of the call to set the remaining credits
            self.check_prefixes([])
        return cast(Quota, self._quota)

    @property
    def status(self) -> bool:
        """Return the status of the HMSL server."""
        try:
            response = self.session.get(f"{self.url}/healthz")
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException:
            return False

    def check(
        self, hashes: Iterable[str], *, full_hashes: bool = False
    ) -> Iterable[Secret]:
        """Check a batch of hashes.
        Supports prefix or full hashes mode.

        Raises a ValueError if a hash is invalid.
        """
        batch_size = HASHES_BATCH_SIZE if full_hashes else PREFIXES_BATCH_SIZE
        for batch in batched(hashes, batch_size):
            if full_hashes:
                yield from self.check_hashes(batch).secrets
            else:
                hints = {make_hint(hash): hash for hash in batch}
                for match in self.check_prefixes(batch).matches:
                    if match.hint in hints:
                        hash = hints[match.hint]
                        yield match.decrypt(hash)

    def query(
        self, hashes: Iterable[str], *, full_hashes: bool = False
    ) -> Iterable[Union[Secret, Match]]:
        """Check a batch of hashes.
        Don't decrypt payloads, return them as is.
        This is mostly useful for the `hmsl query` command,
        clients should use check() instead.
        """
        batch_size = HASHES_BATCH_SIZE if full_hashes else PREFIXES_BATCH_SIZE
        for batch in batched(hashes, batch_size):
            if full_hashes:
                yield from self.check_hashes(batch).secrets
            else:
                yield from self.check_prefixes(batch).matches

    def check_hashes(self, hashes: List[str]) -> SecretsResponse:
        """Audit a batch of full hashes."""
        response = self._query("/v1/hashes", {"hashes": hashes})
        return SecretsResponse(
            secrets=[
                Secret(
                    hash=secret["hash"],
                    count=secret["count"],
                    url=secret["location"]["u"] if secret["location"] else None,
                )
                for secret in response["secrets"]
            ]
        )

    def check_prefixes(self, prefixes_or_hashes: List[str]) -> PrefixesResponse:
        """Audit a batch of prefixes."""
        # Make sure we don't send full hashes
        prefixes = [element[: self.prefix_length] for element in prefixes_or_hashes]
        response = self._query("/v1/prefixes", {"prefixes": prefixes})
        return PrefixesResponse(
            matches=[
                Match(hint=match["hint"], payload=match["payload"])
                for match in response["matches"]
            ]
        )

    def _query(self, endpoint: str, body: Dict[str, List[str]]) -> Any:
        """Send a query to the HMSL service."""
        if self.jwt is not None:
            headers = {"Authorization": f"Bearer {self.jwt}"}
        else:
            headers = {}
        response = self.session.post(
            self.url + endpoint,
            json=body,
            headers=headers,
        )
        response.raise_for_status()
        now = datetime.now().replace(microsecond=0)
        self._quota = Quota(
            remaining=int(response.headers["RateLimit-Remaining"]),
            limit=int(response.headers["RateLimit-Limit"]),
            reset=now + timedelta(seconds=1 + int(response.headers["RateLimit-Reset"])),
        )
        return response.json()
