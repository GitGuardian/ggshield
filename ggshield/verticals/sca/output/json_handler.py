from typing import Any, Dict, cast

from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)
from ggshield.verticals.sca.output.handler import SCAOutputHandler
from ggshield.verticals.sca.output.schemas import (
    SCAJSONScanAllOutputSchema,
    SCAJSONScanDiffOutputSchema,
)


class SCAJsonOutputHandler(SCAOutputHandler):
    def _process_scan_all_impl(self, scan: SCAScanAllVulnerabilityCollection) -> str:
        scan_dict = self.create_scan_all_dict(scan)
        schema = SCAJSONScanAllOutputSchema
        serialized_result = schema.load(scan_dict)
        text = schema.dumps(serialized_result)
        return cast(str, text)

    def _process_scan_diff_impl(self, scan: SCAScanDiffVulnerabilityCollection) -> str:
        scan_dict = (
            scan.result.to_dict()
            if scan.result is not None
            else {"scanned_files": [], "added_vulns": [], "removed_vulns": []}
        )
        schema = SCAJSONScanDiffOutputSchema
        serialized_result = schema.load(scan_dict)
        text = schema.dumps(serialized_result)
        return cast(str, text)

    @staticmethod
    def create_scan_all_dict(scan: SCAScanAllVulnerabilityCollection) -> Dict[str, Any]:
        if scan.result is None:
            return {"scanned_files": [], "found_package_vulns": [], "total_vulns": 0}
        scan_dict = scan.result.to_dict()

        scan_dict["total_vulns"] = 0
        for file in scan_dict["found_package_vulns"]:
            scan_dict["total_vulns"] += len(file["package_vulns"])

        return scan_dict
