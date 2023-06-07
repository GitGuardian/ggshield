from typing import Any, Dict, cast

from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection
from ggshield.iac.output.iac_output_handler import IaCOutputHandler
from ggshield.iac.output.schemas import IaCJSONScanResultSchema


class IaCJSONOutputHandler(IaCOutputHandler):
    def _process_scan_impl(self, scan: IaCPathScanCollection) -> str:
        scan_dict = IaCJSONOutputHandler.create_scan_dict(scan)
        text = IaCJSONScanResultSchema().dumps(scan_dict)
        return cast(str, text)

    # TODO: Determine a design & implement
    def _process_diff_scan_impl(self, scan: IaCDiffScanCollection) -> str:
        return "WIP: this will be the JSON output for diff scan."

    @staticmethod
    def create_scan_dict(scan: IaCPathScanCollection) -> Dict[str, Any]:
        if scan.result is None:
            return {
                "id": scan.id,
                "type": scan.type.value,
                "total_incidents": 0,
                "entities_with_incidents": [],
            }
        scan_dict = scan.result.to_dict()
        scan_dict["total_incidents"] = 0

        for entity in scan_dict["entities_with_incidents"]:
            total_incidents = len(entity["incidents"])
            entity["total_incidents"] = total_incidents
            scan_dict["total_incidents"] += total_incidents

        return scan_dict
