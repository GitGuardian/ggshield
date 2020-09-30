from typing import Any, Dict, List, Tuple, Union

from pygitguardian.models import PolicyBreak

from ggshield.filter import censor_content, leak_dictionary_by_ignore_sha
from ggshield.output.output_handler import OutputHandler
from ggshield.scan import Result
from ggshield.scan.scannable import ScanCollection
from ggshield.text_utils import Line
from ggshield.utils import Filemode, get_lines_from_content, update_policy_break_matches


class JSONHandler(OutputHandler):
    def process_scan(
        self, scan: ScanCollection, top: bool = True
    ) -> Tuple[Union[List[Dict[str, Any]], Dict[str, Any]], int]:
        scan_dict: Dict[str, Any] = {"id": scan.id}
        return_code = 0

        if scan.results:
            return_code = 1
            for result in scan.results:
                scan_dict.setdefault("results", []).append(self.process_result(result))

        if scan.scans:
            for inner_scan in scan.scans:
                inner_scan_dict, inner_return_code = self.process_scan(
                    inner_scan, top=False
                )
                scan_dict.setdefault("scans", []).append(inner_scan_dict)
                return_code = max(return_code, inner_return_code)

        return scan_dict, return_code

    def process_result(self, result: Result) -> Dict[str, Any]:
        result_dict: Dict[str, Any] = {
            "filename": result.filename,
            "mode": result.filemode.name,
            "issues": [],
        }
        content = result.content
        is_patch = result.filemode != Filemode.FILE

        if not self.show_secrets:
            content = censor_content(result.content, result.scan.policy_breaks)

        lines = get_lines_from_content(
            content, result.filemode, is_patch, self.show_secrets
        )
        sha_dict = leak_dictionary_by_ignore_sha(result.scan.policy_breaks)

        result_dict["total_issues"] = len(sha_dict)

        for ignore_sha, policy_breaks in sha_dict.items():
            flattened_dict = self.flattened_policy_break(
                ignore_sha,
                policy_breaks,
                lines,
                is_patch,
            )
            result_dict["issues"].append(flattened_dict)

        return result_dict

    def flattened_policy_break(
        self,
        ignore_sha: str,
        policy_breaks: List[PolicyBreak],
        lines: List[Line],
        is_patch: bool,
    ) -> Dict[str, Any]:
        flattened_dict: Dict[str, Any] = {
            "matches": [],
            "ignore_sha": ignore_sha,
            "policy": policy_breaks[0].policy,
            "break_type": policy_breaks[0].break_type,
            "occurences": len(policy_breaks),
        }
        for policy_break in policy_breaks:
            update_policy_break_matches(policy_break.matches, lines, is_patch)
            flattened_dict["matches"].extend(policy_break.matches)

        return flattened_dict
