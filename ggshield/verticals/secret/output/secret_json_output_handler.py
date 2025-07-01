import dataclasses
from typing import Any, Dict, List, cast

from pygitguardian.client import VERSIONS
from pygitguardian.models import SecretIncident

from ggshield.verticals.secret.extended_match import ExtendedMatch

from ..secret_scan_collection import (
    Error,
    Result,
    Secret,
    SecretScanCollection,
    group_secrets_by_ignore_sha,
)
from .schemas import JSONScanCollectionSchema
from .secret_output_handler import SecretOutputHandler


class SecretJSONOutputHandler(SecretOutputHandler):
    def create_scan_dict(
        self,
        scan: SecretScanCollection,
        incident_details: Dict[str, SecretIncident],
        top: bool = True,
    ) -> Dict[str, Any]:
        scan_dict: Dict[str, Any] = {
            "id": scan.id,
            "type": scan.type,
            "total_incidents": 0,
            "total_occurrences": 0,
        }
        if scan.extra_info:
            scan_dict["extra_info"] = scan.extra_info

        if top:
            scan_dict["secrets_engine_version"] = VERSIONS.secrets_engine_version

        if scan.results:
            for result in scan.results.results:
                result_dict = self.process_result(result, incident_details)
                scan_dict.setdefault("results", []).append(result_dict)
                scan_dict["total_incidents"] += result_dict["total_incidents"]
                scan_dict["total_occurrences"] += result_dict["total_occurrences"]

            for error in scan.results.errors:
                error_dict = self.process_error(error)
                scan_dict.setdefault("errors", []).append(error_dict)

        if scan.scans:
            for inner_scan in scan.scans_with_results:
                inner_scan_dict = self.create_scan_dict(
                    inner_scan, top=False, incident_details=incident_details
                )
                scan_dict.setdefault("scans", []).append(inner_scan_dict)
                scan_dict["total_incidents"] += inner_scan_dict["total_incidents"]
                scan_dict["total_occurrences"] += inner_scan_dict["total_occurrences"]
        return scan_dict

    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        if self.with_incident_details:
            assert self.client
            incident_details = scan.get_incident_details(self.client)
        else:
            incident_details = {}
        scan_dict = self.create_scan_dict(
            scan, top=True, incident_details=incident_details
        )
        text = JSONScanCollectionSchema().dumps(scan_dict)
        # dumps() return type is not defined, so cast `text`, otherwise mypy complains
        return cast(str, text)

    def process_result(
        self, result: Result, incident_details: Dict[str, SecretIncident]
    ) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = {
            "filename": result.path,
            "mode": result.filemode.name,
            "incidents": [],
            "total_occurrences": 0,
            "total_incidents": 0,
        }
        sha_dict = group_secrets_by_ignore_sha(result.secrets)
        result_dict["total_incidents"] = len(sha_dict)

        if not self.show_secrets:
            result.censor()

        for ignore_sha, secrets in sha_dict.items():
            flattened_dict = self.serialized_secret(
                ignore_sha, secrets, incident_details
            )
            result_dict["incidents"].append(flattened_dict)
            result_dict["total_occurrences"] += flattened_dict["total_occurrences"]
        return result_dict

    @staticmethod
    def process_error(error: Error) -> Dict[str, Any]:
        error_dict: Dict[str, Any] = {
            "files": [
                {
                    "filename": filename,
                    "mode": filemode.name,
                }
                for filename, filemode in error.files
            ],
            "description": error.description,
        }
        return error_dict

    def serialized_secret(
        self,
        ignore_sha: str,
        secrets: List[Secret],
        incident_details: Dict[str, SecretIncident],
    ) -> Dict[str, Any]:
        flattened_dict: Dict[str, Any] = {
            "occurrences": [],
            "ignore_sha": ignore_sha,
            "policy": secrets[0].policy,
            "detector": secrets[0].detector_display_name,
            "total_occurrences": len(secrets),
        }

        if secrets[0].documentation_url:
            flattened_dict["detector_documentation"] = secrets[0].documentation_url

        if secrets[0].validity:
            flattened_dict["validity"] = secrets[0].validity

        if secrets[0].known_secret:
            flattened_dict["known_secret"] = secrets[0].known_secret
            flattened_dict["incident_url"] = secrets[0].incident_url
            assert secrets[0].incident_url
            details = incident_details.get(secrets[0].incident_url)
            if details is not None:
                flattened_dict["incident_details"] = details

        if secrets[0].ignore_reason is not None:
            flattened_dict["ignore_reason"] = dataclasses.asdict(
                secrets[0].ignore_reason
            )

        if secrets[0].is_vaulted:
            flattened_dict["secret_vaulted"] = secrets[0].is_vaulted

        # Add vault information if available
        if secrets[0].vault_path is not None:
            flattened_dict["vault_type"] = secrets[0].vault_type
            flattened_dict["vault_name"] = secrets[0].vault_name
            flattened_dict["vault_path"] = secrets[0].vault_path
            flattened_dict["vault_path_count"] = secrets[0].vault_path_count

        for secret in secrets:
            flattened_dict["occurrences"].extend(self.serialize_secret_matches(secret))

        return flattened_dict

    def serialize_secret_matches(
        self,
        secret: Secret,
    ) -> List[Dict[str, Any]]:
        """
        Serialize secret matches. The method uses MatchSpan to get the start and
        end index of the match.
        Returns a list of matches.
        """
        matches_list: List[Dict[str, Any]] = []
        for match in secret.matches:
            assert isinstance(match, ExtendedMatch)

            match_dict: Dict[str, Any] = {
                "match": match.match,
                "match_type": match.match_type,
                "line_start": match.line_start,
                "line_end": match.line_end,
                "index_start": match.span.column_index_start,
                "index_end": match.span.column_index_end,
            }
            if match.pre_line_start is not None and match.pre_line_end is not None:
                match_dict["pre_line_start"] = match.pre_line_start
                match_dict["pre_line_end"] = match.pre_line_end
            if match.post_line_start is not None and match.post_line_end is not None:
                match_dict["post_line_start"] = match.post_line_start
                match_dict["post_line_end"] = match.post_line_end
            matches_list.append(match_dict)
        return matches_list
