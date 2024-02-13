import json
from typing import Any, Dict, List, cast

from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)
from ggshield.verticals.sca.output.handler import SCAOutputHandler


class SCAJsonOutputHandler(SCAOutputHandler):
    def _process_scan_all_impl(self, scan: SCAScanAllVulnerabilityCollection) -> str:
        scan_dict = SCAJsonOutputHandler.create_scan_all_dict(scan)
        text = json.dumps(scan_dict)
        return cast(str, text)

    def _process_scan_diff_impl(self, scan: SCAScanDiffVulnerabilityCollection) -> str:
        result_without_ignored = scan.get_result_without_ignored()
        scan_dict = (
            result_without_ignored.to_dict()
            if result_without_ignored is not None
            else {"scanned_files": [], "added_vulns": [], "removed_vulns": []}
        )

        del scan_dict["source_found"]
        SCAJsonOutputHandler.remove_vuln_keys_from_raw_packages(
            scan_dict["added_vulns"]
        )
        SCAJsonOutputHandler.remove_vuln_keys_from_raw_packages(
            scan_dict["removed_vulns"]
        )

        return json.dumps(scan_dict)

    @staticmethod
    def create_scan_all_dict(scan: SCAScanAllVulnerabilityCollection) -> Dict[str, Any]:
        result = scan.get_result_without_ignored()
        if result is None:
            return {"scanned_files": [], "found_package_vulns": [], "total_vulns": 0}
        scan_dict = result.to_dict()

        scan_dict["total_vulns"] = 0
        for file in scan_dict["found_package_vulns"]:
            scan_dict["total_vulns"] += len(file["package_vulns"])

        del scan_dict["source_found"]
        SCAJsonOutputHandler.remove_vuln_keys_from_raw_packages(
            scan_dict["found_package_vulns"]
        )

        return scan_dict

    @staticmethod
    def remove_vuln_keys_from_raw_packages(packages: List[Dict[str, Any]]) -> None:
        """Deletes in-place elements from the raw response that should not appear in the output."""
        for package in packages:
            for package_vuln in package["package_vulns"]:
                for vuln in package_vuln["vulns"]:
                    for key_to_delete in (
                        "url",
                        "status",
                        "ignored_until",
                        "ignore_reason",
                        "ignore_comment",
                    ):
                        del vuln[key_to_delete]
