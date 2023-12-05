from typing import Any, Dict, cast

from ggshield.verticals.iac.collection.iac_diff_scan_collection import (
    IaCDiffScanCollection,
)
from ggshield.verticals.iac.collection.iac_path_scan_collection import (
    IaCPathScanCollection,
)
from ggshield.verticals.iac.output.iac_output_handler import IaCOutputHandler
from ggshield.verticals.iac.output.schemas import (
    IaCJSONScanDiffResultSchema,
    IaCJSONScanResultSchema,
)


class IaCJSONOutputHandler(IaCOutputHandler):
    def _process_scan_impl(self, scan: IaCPathScanCollection) -> str:
        scan_dict = IaCJSONOutputHandler.create_scan_dict(scan)
        text = IaCJSONScanResultSchema().dumps(scan_dict)
        return cast(str, text)

    def _process_skip_scan_impl(self) -> str:
        return "{}"

    def _process_skip_diff_scan_impl(self) -> str:
        return "{}"

    def _process_diff_scan_impl(self, scan: IaCDiffScanCollection) -> str:
        scan_dict = IaCJSONOutputHandler.create_diff_scan_dict(scan)
        text = IaCJSONScanDiffResultSchema().dumps(scan_dict)
        return cast(str, text)

    @staticmethod
    def create_scan_dict(scan: IaCPathScanCollection) -> Dict[str, Any]:
        result_without_ignored = scan.get_result_without_ignored()
        if result_without_ignored is None:
            return {
                "id": scan.id,
                "type": scan.type.value,
                "total_incidents": 0,
                "entities_with_incidents": [],
            }
        scan_dict = result_without_ignored.to_dict()
        scan_dict["total_incidents"] = 0

        for entity in scan_dict["entities_with_incidents"]:
            total_incidents = len(entity["incidents"])
            entity["total_incidents"] = total_incidents
            scan_dict["total_incidents"] += total_incidents

        return scan_dict

    @staticmethod
    def create_diff_scan_dict(scan: IaCDiffScanCollection) -> Dict[str, Any]:
        result_without_ignored = scan.get_result_without_ignored()
        if result_without_ignored is None:
            return {
                "id": scan.id,
                "type": scan.type.value,
                "total_incidents": 0,
                "entities_with_incidents": {
                    "unchanged": [],
                    "new": [],
                    "deleted": [],
                },
            }
        scan_dict = result_without_ignored.to_dict()

        for category in scan_dict["entities_with_incidents"]:
            for file_result in scan_dict["entities_with_incidents"][category]:
                file_result["total_incidents"] = len(file_result["incidents"])

        return scan_dict
