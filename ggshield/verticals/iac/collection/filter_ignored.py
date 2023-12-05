from typing import List

from pygitguardian.iac_models import IaCFileResult, IaCVulnerability


def filter_unignored_incidents(
    incidents: List[IaCVulnerability],
) -> List[IaCVulnerability]:
    """Removes ignored incidents from the given list"""
    return [incident for incident in incidents if incident.status != "IGNORED"]


def filter_unignored_files(files: List[IaCFileResult]) -> List[IaCFileResult]:
    unignored_files: List[IaCFileResult] = []
    for file in files:
        unignored_incidents = filter_unignored_incidents(file.incidents)
        if len(unignored_incidents) > 0:
            unignored_files.append(
                IaCFileResult(filename=file.filename, incidents=unignored_incidents)
            )
    return unignored_files
