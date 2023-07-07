from typing import Any, Dict, cast

from pygitguardian.iac_models import IaCDiffScanEntities, IaCFileResult

from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection
from ggshield.iac.output.iac_output_handler import IaCOutputHandler
from ggshield.iac.output.schemas import (
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

    @staticmethod
    def create_diff_scan_dict(scan: IaCDiffScanCollection) -> Dict[str, Any]:
        ret: Dict[str, Any] = {
            "added_vulns": [],
            "persisting_vulns": [],
            "removed_vulns": [],
        }

        def file_result_transform(file_result: IaCFileResult) -> Dict[str, Any]:
            return dict(
                filename=file_result.filename,
                incidents=file_result.incidents,
                total_incidents=len(file_result.incidents),
            )

        if scan.result is not None and isinstance(
            scan.result.entities_with_incidents, IaCDiffScanEntities
        ):
            for file_result in scan.result.entities_with_incidents.new:
                ret["added_vulns"].append(file_result_transform(file_result))
            for file_result in scan.result.entities_with_incidents.unchanged:
                ret["persisting_vulns"].append(file_result_transform(file_result))
            for file_result in scan.result.entities_with_incidents.deleted:
                ret["removed_vulns"].append(file_result_transform(file_result))
        return ret
