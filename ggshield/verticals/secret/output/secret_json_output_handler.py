from typing import Any, Dict, List, cast

from pygitguardian.client import VERSIONS
from pygitguardian.models import PolicyBreak

from ggshield.core.filter import leak_dictionary_by_ignore_sha

from ..secret_scan_collection import Error, Result, SecretScanCollection
from .schemas import JSONScanCollectionSchema
from .secret_output_handler import SecretOutputHandler


class SecretJSONOutputHandler(SecretOutputHandler):
    def _process_scan_impl(self, scan: SecretScanCollection) -> str:
        scan_dict = self.create_scan_dict(scan, top=True)
        text = JSONScanCollectionSchema().dumps(scan_dict)
        # dumps() return type is not defined, so cast `text`, otherwise mypy complains
        return cast(str, text)

    def create_scan_dict(
        self, scan: SecretScanCollection, top: bool = True
    ) -> Dict[str, Any]:
        scan_dict: Dict[str, Any] = {
            "id": scan.id,
            "type": scan.type,
            "total_incidents": 0,
            "total_occurrences": 0,
        }
        if scan.extra_info:
            scan_dict["extra_info"] = scan.extra_info

        if top and scan.has_results:
            scan_dict["secrets_engine_version"] = VERSIONS.secrets_engine_version

        if scan.results:
            for result in scan.results.results:
                result_dict = self.process_result(result)
                scan_dict.setdefault("results", []).append(result_dict)
                scan_dict["total_incidents"] += result_dict["total_incidents"]
                scan_dict["total_occurrences"] += result_dict["total_occurrences"]

            for error in scan.results.errors:
                error_dict = self.process_error(error)
                scan_dict.setdefault("errors", []).append(error_dict)

        if scan.scans:
            for inner_scan in scan.scans_with_results:
                inner_scan_dict = self.create_scan_dict(inner_scan, top=False)
                scan_dict.setdefault("scans", []).append(inner_scan_dict)
                scan_dict["total_incidents"] += inner_scan_dict["total_incidents"]
                scan_dict["total_occurrences"] += inner_scan_dict["total_occurrences"]
        return scan_dict

    def process_result(self, result: Result) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = {
            "filename": result.file.path,
            "mode": result.filemode.name,
            "incidents": [],
            "total_occurrences": 0,
            "total_incidents": 0,
        }
        sha_dict = leak_dictionary_by_ignore_sha(result.scan.policy_breaks)
        result_dict["total_incidents"] = len(sha_dict)
        result.enrich_matches()

        if not self.show_secrets:
            result.censor()

        for ignore_sha, policy_breaks in sha_dict.items():
            flattened_dict = self.flattened_policy_break(
                ignore_sha,
                policy_breaks,
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

    def flattened_policy_break(
        self,
        ignore_sha: str,
        policy_breaks: List[PolicyBreak],
    ) -> Dict[str, Any]:
        flattened_dict: Dict[str, Any] = {
            "occurrences": [],
            "ignore_sha": ignore_sha,
            "policy": policy_breaks[0].policy,
            "break_type": policy_breaks[0].break_type,
            "total_occurrences": len(policy_breaks),
        }

        if policy_breaks[0].validity:
            flattened_dict["validity"] = policy_breaks[0].validity

        if policy_breaks[0].known_secret:
            flattened_dict["known_secret"] = policy_breaks[0].known_secret
            flattened_dict["incident_url"] = policy_breaks[0].incident_url

        for policy_break in policy_breaks:
            flattened_dict["occurrences"].extend(policy_break.matches)

        return flattened_dict
