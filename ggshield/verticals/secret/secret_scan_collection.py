from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple, Union, cast

from pygitguardian.models import Match, ScanResult

from ggshield.core.errors import UnexpectedError
from ggshield.core.filter import group_policy_breaks_by_ignore_sha
from ggshield.core.lines import Line, get_lines_from_content
from ggshield.core.scan.scannable import Scannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret.extended_match import ExtendedMatch


class Result:
    """
    Return model for a scan which zips the information
    between the Scan result and its input file.
    """

    filename: str  # Name of the file/patch scanned
    filemode: Filemode
    path: Path
    url: str
    scan: ScanResult  # Result of content scan

    def __init__(self, file: Scannable, scan: ScanResult):
        self.filename = file.filename
        self.filemode = file.filemode
        self.path = file.path
        self.url = file.url
        self.scan = scan
        lines = get_lines_from_content(file.content, self.filemode)
        self.enrich_matches(lines)

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Result):
            return False
        return (
            self.filename == other.filename
            and self.filemode == other.filemode
            and self.path == other.path
            and self.url == other.url
            and self.scan == other.scan
        )

    @property
    def is_on_patch(self) -> bool:
        return self.filemode != Filemode.FILE

    def enrich_matches(self, lines: List[Line]) -> None:
        if len(lines) == 0:
            raise UnexpectedError("Parsing of scan result failed.")
        for policy_break in self.scan.policy_breaks:
            policy_break.matches = cast(
                List[Match],
                [
                    ExtendedMatch.from_match(match, lines, self.is_on_patch)
                    for match in policy_break.matches
                ],
            )

    def censor(self) -> None:
        for policy_break in self.scan.policy_breaks:
            for extended_match in policy_break.matches:
                cast(ExtendedMatch, extended_match).censor()

    @property
    def has_policy_breaks(self) -> bool:
        return self.scan.has_policy_breaks


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
        error = Error(files=[], description=str(exc))
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

        (
            self.known_secrets_count,
            self.new_secrets_count,
        ) = self._get_known_new_secrets_count()

    @property
    def has_new_secrets(self) -> bool:
        return self.new_secrets_count > 0

    @property
    def has_secrets(self) -> bool:
        return (self.new_secrets_count + self.known_secrets_count) > 0

    @property
    def scans_with_results(self) -> List["SecretScanCollection"]:
        if self.scans:
            return [scan for scan in self.scans if scan.results]
        return []

    @property
    def has_results(self) -> bool:
        return bool(self.results and self.results.results)

    def _get_known_new_secrets_count(self) -> Tuple[int, int]:
        policy_breaks = []
        for result in self.get_all_results():
            for policy_break in result.scan.policy_breaks:
                policy_breaks.append(policy_break)

        known_secrets_count = 0
        new_secrets_count = 0
        sha_dict = group_policy_breaks_by_ignore_sha(policy_breaks)

        for ignore_sha, policy_breaks in sha_dict.items():
            if policy_breaks[0].known_secret:
                known_secrets_count += 1
            else:
                new_secrets_count += 1

        return known_secrets_count, new_secrets_count

    def get_all_results(self) -> Iterable[Result]:
        """Returns an iterable on all results and sub-scan results"""
        if self.results:
            yield from self.results.results
        if self.scans:
            for scan in self.scans:
                if scan.results:
                    yield from scan.results.results
