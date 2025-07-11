import hashlib
import operator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Counter,
    Dict,
    Iterable,
    List,
    NamedTuple,
    Optional,
    Tuple,
    Union,
    cast,
)

from pygitguardian import GGClient
from pygitguardian.models import (
    Detail,
    DiffKind,
    PolicyBreak,
    ScanResult,
    SecretIncident,
)

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import handle_api_error
from ggshield.core.filter import is_in_ignored_matches
from ggshield.core.lines import get_lines_from_content
from ggshield.core.scan import Scannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret.extended_match import ExtendedMatch


class IgnoreKind(str, Enum):
    IGNORED_MATCH = "Match ignored via local .gitguardian yaml"
    IGNORED_DETECTOR = "Detector ignored via local .gitguardian yaml"
    KNOWN_SECRET = "Secret is known in dashboard and --ignore-known-secrets is used"
    NOT_INTRODUCED = "Secret was not in added in commit"
    BACKEND_EXCLUDED = "Excluded by dashboard"

    def __str__(self):
        return self.name.lower()


@dataclass(frozen=True)
class IgnoreReason:
    kind: IgnoreKind
    detail: Optional[str] = None

    def to_human_readable(self):
        res = f"{self.kind.value}"
        if self.detail:
            res += f" ({self.detail})"
        return res


def compute_ignore_reason(
    policy_break: PolicyBreak, secret_config: SecretConfig
) -> Optional[IgnoreReason]:
    """Computes the possible ignore reason associated with a PolicyBreak"""
    ignore_reason = None
    if policy_break.diff_kind in {DiffKind.DELETION, DiffKind.CONTEXT}:
        ignore_reason = IgnoreReason(IgnoreKind.NOT_INTRODUCED)
    elif policy_break.is_excluded:
        ignore_reason = IgnoreReason(
            IgnoreKind.BACKEND_EXCLUDED, policy_break.exclude_reason
        )
    elif is_in_ignored_matches(policy_break, secret_config.ignored_matches or []):
        ignore_reason = IgnoreReason(IgnoreKind.IGNORED_MATCH)
    elif policy_break.break_type in secret_config.ignored_detectors:
        ignore_reason = IgnoreReason(IgnoreKind.IGNORED_DETECTOR)
    elif secret_config.ignore_known_secrets and policy_break.known_secret:
        ignore_reason = IgnoreReason(IgnoreKind.KNOWN_SECRET)

    return ignore_reason


@dataclass
class Secret:
    """GGShield specific model to handle policy-breaks.
    Named Secret since we are dropping other kind of policy breaks.
    """

    detector_display_name: str
    detector_name: Optional[str]
    detector_group_name: Optional[str]
    documentation_url: Optional[str]
    validity: str
    known_secret: bool
    incident_url: Optional[str]
    matches: List[ExtendedMatch]
    ignore_reason: Optional[IgnoreReason]
    diff_kind: Optional[DiffKind]
    is_vaulted: bool
    vault_type: Optional[str]
    vault_name: Optional[str]
    vault_path: Optional[str]
    vault_path_count: Optional[int]

    @property
    def policy(self) -> str:
        return "Secrets detection"

    @property
    def is_ignored(self) -> bool:
        return self.ignore_reason is not None

    def get_ignore_sha(self) -> str:
        hashable = "".join(
            [
                f"{match.match},{match.match_type}"
                for match in sorted(self.matches, key=operator.attrgetter("match_type"))
            ]
        )

        return hashlib.sha256(hashable.encode("UTF-8")).hexdigest()


def group_secrets_by_ignore_sha(
    secrets: List[Secret],
) -> Dict[str, List[Secret]]:
    """
    Group policy breaks by their ignore sha.
    """
    sha_dict: Dict[str, List[Secret]] = {}
    for secret in secrets:
        sha_dict.setdefault(secret.get_ignore_sha(), []).append(secret)

    return sha_dict


@dataclass
class Result:
    """
    Return model for a scan which zips the information
    between the Scan result and its input file.
    """

    filename: str  # Name of the file/patch scanned
    filemode: Filemode
    path: Path
    url: str
    secrets: List[Secret]
    ignored_secrets_count_by_kind: Counter[IgnoreKind]

    @property
    def is_on_patch(self) -> bool:
        return self.filemode != Filemode.FILE

    def censor(self) -> None:
        for secret in self.secrets:
            for extended_match in secret.matches:
                cast(ExtendedMatch, extended_match).censor()

    @property
    def has_secrets(self) -> bool:
        return len(self.secrets) > 0

    @classmethod
    def from_scan_result(
        cls, file: Scannable, scan_result: ScanResult, secret_config: SecretConfig
    ) -> "Result":
        """Creates a Result from a Scannable and a ScanResult.
        - Removes ignored policy breaks
        - replace matches by ExtendedMatches
        """

        to_keep: List[Tuple[PolicyBreak, Optional[IgnoreReason]]] = []
        ignored_secrets_count_by_kind = Counter()
        for policy_break in scan_result.policy_breaks:
            ignore_reason = compute_ignore_reason(policy_break, secret_config)
            if ignore_reason is not None:
                if secret_config.all_secrets:
                    to_keep.append((policy_break, ignore_reason))
                else:
                    ignored_secrets_count_by_kind[ignore_reason.kind] += 1
            else:
                to_keep.append((policy_break, None))

        result = Result(
            filename=file.filename,
            filemode=file.filemode,
            path=file.path,
            url=file.url,
            secrets=[],
            ignored_secrets_count_by_kind=ignored_secrets_count_by_kind,
        )

        lines = get_lines_from_content(file.content, file.filemode)
        secrets = [
            Secret(
                validity=policy_break.validity,
                known_secret=policy_break.known_secret,
                incident_url=policy_break.incident_url,
                detector_display_name=policy_break.break_type,
                detector_name=policy_break.detector_name,
                detector_group_name=policy_break.detector_group_name,
                documentation_url=policy_break.documentation_url,
                matches=[
                    ExtendedMatch.from_match(match, lines, result.is_on_patch)
                    for match in policy_break.matches
                ],
                ignore_reason=ignore_reason,
                diff_kind=policy_break.diff_kind,
                is_vaulted=policy_break.is_vaulted,
                vault_type=getattr(policy_break, "vault_type", None),
                vault_name=getattr(policy_break, "vault_name", None),
                vault_path=getattr(policy_break, "vault_path", None),
                vault_path_count=getattr(policy_break, "vault_path_count", None),
            )
            for policy_break, ignore_reason in to_keep
        ]

        result.secrets = secrets
        return result


class Error(NamedTuple):
    files: List[Tuple[str, Filemode]]
    description: str  # Description of the error


@dataclass
class Results:
    """
    Return model for a scan with the results and errors of the scan

    Not a NamedTuple like the others because it causes mypy 0.961 to crash on the
    `from_exception()` method (!)

    Similar crash: https://github.com/python/mypy/issues/12629
    """

    results: List[Result] = field(default_factory=list)
    errors: List[Error] = field(default_factory=list)

    @staticmethod
    def from_exception(exc: Exception) -> "Results":
        """Create a Results representing a failure"""
        exc_class_name = exc.__class__.__name__
        description = f"{exc_class_name}: {str(exc) or '-'}"
        error = Error(files=[], description=description)
        return Results(results=[], errors=[error])

    def extend(self, others: "Results") -> None:
        self.results.extend(others.results)
        self.errors.extend(others.errors)

    @property
    def has_secrets(self) -> bool:
        return any(x.has_secrets for x in self.results)


class SecretScanCollection:
    id: str
    type: str
    results: Optional[Results] = None
    scans: Optional[List["SecretScanCollection"]] = None
    optional_header: Optional[str] = None  # To be printed in Text Output
    extra_info: Optional[Dict[str, str]] = None  # To be included in JSON Output

    def __init__(
        self,
        id: Union[str, Path],
        type: str,
        results: Optional[Results] = None,
        scans: Optional[List["SecretScanCollection"]] = None,
        optional_header: Optional[str] = None,
        extra_info: Optional[Dict[str, str]] = None,
    ):
        self.id = str(id)
        self.type = type
        self.results = results
        self.scans = scans
        self.optional_header = optional_header
        self.extra_info = extra_info

        self.total_secrets_count = sum(
            len(result.secrets) for result in self.get_all_results()
        )

    @property
    def scans_with_results(self) -> List["SecretScanCollection"]:
        if self.scans:
            return [scan for scan in self.scans if scan.results]
        return []

    def get_all_results(self) -> Iterable[Result]:
        """Returns an iterable on all results and sub-scan results"""
        if self.results:
            yield from self.results.results
        if self.scans:
            for scan in self.scans:
                if scan.results:
                    yield from scan.results.results

    def get_incident_details(self, client: GGClient) -> Dict[str, SecretIncident]:
        incident_details: dict[str, SecretIncident] = {}
        for result in self.get_all_results():
            for secret in result.secrets:
                url = secret.incident_url
                if url and url not in incident_details:
                    incident_id = int(url.split("/")[-1])
                    resp = client.retrieve_secret_incident(
                        incident_id, with_occurrences=0
                    )
                    if isinstance(resp, SecretIncident):
                        incident_details[url] = resp
                    else:
                        assert isinstance(resp, Detail)
                        handle_api_error(resp)
        return incident_details
