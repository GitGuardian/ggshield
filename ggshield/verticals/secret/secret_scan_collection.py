from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Tuple, Union, cast

from pygitguardian import GGClient
from pygitguardian.models import (
    Detail,
    DiffKind,
    Match,
    PolicyBreak,
    ScanResult,
    SecretIncident,
)

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.errors import UnexpectedError, handle_api_error
from ggshield.core.filter import is_in_ignored_matches
from ggshield.core.lines import Line, get_lines_from_content
from ggshield.core.scan import Scannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret.extended_match import ExtendedMatch


class IgnoreReason(str, Enum):
    IGNORED_MATCH = "ignored_match"
    IGNORED_DETECTOR = "ignored_detector"
    KNOWN_SECRET = "known_secret"
    NOT_INTRODUCED = "not_introduced"
    BACKEND_EXCLUDED = "backend_excluded"


def compute_ignore_reason(
    policy_break: PolicyBreak, secret_config: SecretConfig
) -> Union[str, None]:
    """Computes the possible ignore reason associated with a PolicyBreak"""
    ignore_reason = None
    if policy_break.diff_kind in {DiffKind.DELETION, DiffKind.CONTEXT}:
        ignore_reason = IgnoreReason.NOT_INTRODUCED
    elif policy_break.is_excluded:
        ignore_reason = f"Excluded from backend ({policy_break.exclude_reason})"
    elif is_in_ignored_matches(policy_break, secret_config.ignored_matches or []):
        ignore_reason = IgnoreReason.IGNORED_MATCH
    elif policy_break.break_type in secret_config.ignored_detectors:
        ignore_reason = IgnoreReason.IGNORED_DETECTOR
    elif secret_config.ignore_known_secrets and policy_break.known_secret:
        ignore_reason = IgnoreReason.KNOWN_SECRET

    return ignore_reason


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
    policy_breaks: List[PolicyBreak]
    ignored_policy_breaks_count_by_reason: Counter[str]

    @property
    def is_on_patch(self) -> bool:
        return self.filemode != Filemode.FILE

    def enrich_matches(self, lines: List[Line]) -> None:
        if len(lines) == 0:
            raise UnexpectedError("Parsing of scan result failed.")
        for policy_break in self.policy_breaks:
            policy_break.matches = cast(
                List[Match],
                [
                    ExtendedMatch.from_match(match, lines, self.is_on_patch)
                    for match in policy_break.matches
                ],
            )

    def censor(self) -> None:
        for policy_break in self.policy_breaks:
            for extended_match in policy_break.matches:
                cast(ExtendedMatch, extended_match).censor()

    @property
    def has_policy_breaks(self) -> bool:
        return len(self.policy_breaks) > 0

    @classmethod
    def from_scan_result(
        cls, file: Scannable, scan_result: ScanResult, secret_config: SecretConfig
    ) -> "Result":
        """Creates a Result from a Scannable and a ScanResult.
        - Removes ignored policy breaks
        - replace matches by ExtendedMatches
        """

        to_keep = []
        ignored_policy_breaks_count_by_reason = Counter()
        for policy_break in scan_result.policy_breaks:
            ignore_reason = compute_ignore_reason(policy_break, secret_config)
            if ignore_reason is not None:
                if secret_config.all_secrets:
                    policy_break.exclude_reason = ignore_reason
                    policy_break.is_excluded = True
                    to_keep.append(policy_break)
                else:
                    ignored_policy_breaks_count_by_reason[ignore_reason] += 1
            else:
                to_keep.append(policy_break)

        result = Result(
            filename=file.filename,
            filemode=file.filemode,
            path=file.path,
            url=file.url,
            policy_breaks=to_keep,
            ignored_policy_breaks_count_by_reason=ignored_policy_breaks_count_by_reason,
        )

        lines = get_lines_from_content(file.content, file.filemode)
        result.enrich_matches(lines)
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
    def has_policy_breaks(self) -> bool:
        return any(x.has_policy_breaks for x in self.results)


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

        self.total_policy_breaks_count = sum(
            len(result.policy_breaks) for result in self.get_all_results()
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
            for policy_break in result.policy_breaks:
                url = policy_break.incident_url
                if url and url not in incident_details:
                    incident_id = int(url.split("/")[-1])
                    resp = client.retrieve_secret_incident(
                        incident_id, with_occurrences=0
                    )
                    if type(resp) == SecretIncident:
                        incident_details[url] = resp
                    else:
                        assert isinstance(resp, Detail)
                        handle_api_error(resp)
        return incident_details
