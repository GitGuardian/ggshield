import json
from typing import Any, Dict, Iterable, List, cast

from pygitguardian.client import VERSIONS
from pygitguardian.models import SecretIncident

from ggshield import __version__ as ggshield_version
from ggshield.core.match_span import MatchSpan
from ggshield.core.text_utils import pluralize

from ..extended_match import ExtendedMatch
from ..secret_scan_collection import Result, Secret, SecretScanCollection
from .secret_output_handler import SecretOutputHandler


SCHEMA_URL = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"


class SecretSARIFOutputHandler(SecretOutputHandler):

    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        incident_details = (
            scan.get_incident_details(self.client)
            if self.with_incident_details and self.client
            else {}
        )
        dct = {
            "version": "2.1.0",
            "$schema": SCHEMA_URL,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "organization": "GitGuardian",
                            "name": "ggshield",
                            "informationUri": "https://github.com/GitGuardian/ggshield",
                            "version": ggshield_version,
                        },
                        "extensions": [
                            {
                                "name": "secret",
                                "version": VERSIONS.secrets_engine_version,
                            }
                        ],
                    },
                    "results": list(
                        _create_sarif_results(scan.get_all_results(), incident_details)
                    ),
                }
            ],
        }
        return json.dumps(dct)


def _create_sarif_results(
    results: Iterable[Result], incident_details: Dict[str, SecretIncident]
) -> Iterable[Dict[str, Any]]:
    """
    Creates SARIF result dicts for our Result instances. Creates one SARIF result dict
    per policy break.
    """
    for result in results:
        for secret in result.secrets:
            yield _create_sarif_result_dict(result.url, secret, incident_details)


def _create_sarif_result_dict(
    url: str,
    secret: Secret,
    incident_details: Dict[str, SecretIncident],
) -> Dict[str, Any]:
    # Prepare message with links to the related location for each match
    matches_str = ", ".join(
        f"[{m.match_type}]({id})" for id, m in enumerate(secret.matches)
    )
    matches_li = "\n".join(
        f"- [{m.match_type}]({id})" for id, m in enumerate(secret.matches)
    )
    extended_matches = cast(List[ExtendedMatch], secret.matches)
    message = (
        f"Secret detected: {secret.detector_display_name}.\nMatches: {matches_str}"
    )
    if secret.documentation_url:
        markdown_message = f"Secret detected: [{secret.detector_display_name}]({secret.documentation_url})"
    else:
        markdown_message = f"Secret detected: {secret.detector_display_name}"

    if secret.is_vaulted:
        if secret.vault_path_count is None:
            markdown_message += "\nSecret found in vault: Yes"
        else:
            vault_count_text = f"({secret.vault_path_count} {pluralize('location', secret.vault_path_count)})"
            markdown_message += f"\nSecret found in vault: Yes {vault_count_text}"
            markdown_message += f"\nVault Type: {secret.vault_type}"
            markdown_message += f"\nVault Name: {secret.vault_name}"
            markdown_message += f"\nSecret Path: {secret.vault_path}"
    else:
        markdown_message += "\nSecret found in vault: No"

    markdown_message += f"\nMatches:\n{matches_li}"

    # Create dict
    dct = {
        "ruleId": secret.detector_display_name,
        "level": "error",
        "message": {
            "text": message,
            "markdown": markdown_message,
        },
        "locations": [
            _create_location_dict(url, [m.span for m in extended_matches]),
        ],
        "relatedLocations": [
            _create_related_location_dict(url, id, m)
            for id, m in enumerate(extended_matches)
        ],
        "partialFingerprints": {
            "secret/v1": secret.get_ignore_sha(),
        },
    }
    if secret.incident_url:
        dct["hostedViewerUri"] = secret.incident_url
        details = incident_details.get(secret.incident_url)
        if details is not None:
            dct["properties"] = {"incidentDetails": details.to_dict()}
    return dct


def _create_location_dict(
    url: str,
    match_spans: List[MatchSpan],
) -> Dict[str, Any]:
    # Create a span from the start of the first match to the end of the last match
    start_pos = min((x.line_index_start, x.column_index_start) for x in match_spans)
    end_pos = max((x.line_index_end, x.column_index_end) for x in match_spans)
    span = MatchSpan(
        line_index_start=start_pos[0],
        line_index_end=end_pos[0],
        column_index_start=start_pos[1],
        column_index_end=end_pos[1],
    )

    return {"physicalLocation": _create_physical_location_dict(url, span)}


def _create_related_location_dict(
    url: str,
    id: int,
    match: ExtendedMatch,
) -> Dict[str, Any]:
    return {
        "id": id,
        "physicalLocation": _create_physical_location_dict(url, match.span),
        "message": {"text": match.match_type},
    }


def _create_physical_location_dict(url: str, match_span: MatchSpan) -> Dict[str, Any]:
    return {
        "artifactLocation": {
            "uri": url,
        },
        "region": {
            "startLine": match_span.line_index_start + 1,
            "startColumn": match_span.column_index_start + 1,
            "endLine": match_span.line_index_end + 1,
            "endColumn": match_span.column_index_end + 1,
        },
    }
