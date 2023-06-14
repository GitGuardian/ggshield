import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Iterator, List, Optional, Union, cast, overload

import requests

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
    url: str


@dataclass
class Match:
    hint: str
    payload: str

    def decrypt(self, hash: str) -> Secret:
        key = bytes.fromhex(hash)
        payload = base64.b64decode(self.payload)
        decrypted = json.loads(decrypt(payload, key))
        return Secret(
            hash=hash,
            count=decrypted["c"],
            url=decrypted["l"]["u"],
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
        self, url: str, jwt: Optional[str] = None, *, prefix_length: int = PREFIX_LENGTH
    ) -> None:
        self.url = url.strip("/")
        self.jwt = jwt
        self.prefix_length = prefix_length
        self._quota: Optional[Quota] = None

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
            response = requests.get(f"{self.url}/healthz")
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException:
            return False

    # Note: these overloads don't perfectly match the implementation,
    # especially since we don't have Literal annotations in Python 3.7.
    # But it's good enough for our usage in ggshield.
    @overload
    def check(self, hashes: Iterable[str]) -> Iterator[Secret]:
        ...

    @overload
    def check(self, hashes: Iterable[str], *, full_hashes: bool) -> Iterator[Secret]:
        ...

    @overload
    def check(
        self, hashes: Iterable[str], *, full_hashes: bool, decrypt: bool
    ) -> Iterator[Match]:
        ...

    def check(  # type: ignore
        self, hashes: Iterable[str], *, full_hashes: bool = False, decrypt: bool = True
    ):
        """Check a batch of hashes.
        Supports prefix or full hashes mode.
        In case of prefix mode, the results are decrypted by default,
        but the raw results are returned if `decrypt` is set to False.
        (this is useful to support the fingerprint/check/decrypt workflow)

        In the case where decrypt is set to False,
        `hashes` can in fact be prefixes by convenience.
        Hashes (or prefixes) are truncated to the prefix length anyway
        so that we never send more data than expected to our servers.

        Raises a ValueError if a hash is invalid.
        """
        batch_size = HASHES_BATCH_SIZE if full_hashes else PREFIXES_BATCH_SIZE
        batch: List[str] = []
        for hash in hashes:
            # Validation
            if not HASH_REGEX.match(hash):
                if full_hashes or decrypt or not PREFIX_REGEX.match(hash):
                    raise ValueError(f"Invalid hash: {hash}")
            batch.append(hash)
            if len(batch) >= batch_size:
                yield from self._check_batch(batch, full_hashes, decrypt)
                batch = []
        if len(batch) > 0:
            yield from self._check_batch(batch, full_hashes, decrypt)

    def _check_batch(
        self, batch: List[str], full_hashes: bool, decrypt: bool = True
    ) -> Iterator[Union[Secret, Match]]:
        if full_hashes:
            yield from self.check_hashes(batch).secrets
            return
        response = self.check_prefixes(batch)
        if decrypt:
            # Compute hints and decrypt secrets
            hints = {make_hint(hash): hash for hash in batch}
            for match in response.matches:
                if match.hint in hints:
                    hash = hints[match.hint]
                    yield match.decrypt(hash)
        else:
            yield from response.matches

    def check_hashes(self, hashes: List[str]) -> SecretsResponse:
        """Audit a batch of full hashes."""
        response = self._query("/v1/hashes", {"hashes": hashes})
        return SecretsResponse(
            secrets=[
                Secret(
                    hash=secret["hash"],
                    count=secret["count"],
                    url=secret["location"]["u"],
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
        response = requests.post(
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
