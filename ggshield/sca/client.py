from typing import Dict, List, Optional, Union

import requests
from pygitguardian.client import GGClient, is_ok, load_detail
from pygitguardian.models import Detail

from ggshield.sca.sca_scan_models import (
    ComputeSCAFilesResult,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAScanParameters,
)


class SCAClient:
    def __init__(self, client: GGClient):
        self._client = client

    @property
    def base_uri(self):
        return self._client.base_uri

    def compute_sca_files(
        self,
        files: List[str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, ComputeSCAFilesResult]:
        if len(files) == 0:
            result = ComputeSCAFilesResult(sca_files=[], potential_siblings=[])
            result.status_code = 200
            return result

        response = self._client.post(
            endpoint="sca/compute_sca_files/",
            data={"files": files},
            extra_headers=extra_headers,
        )
        result: Union[Detail, ComputeSCAFilesResult]
        if is_ok(response):
            result = ComputeSCAFilesResult.from_dict(response.json())
        else:
            result = load_detail(response)

        result.status_code = response.status_code
        return result

    def sca_scan_directory(
        self,
        tar_file: bytes,
        scan_parameters: SCAScanParameters,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, SCAScanAllOutput]:
        """
        Generates tar archive associated with filenames and launches
        SCA scan via SCA public API.
        """

        result: Union[Detail, SCAScanAllOutput]

        try:
            # bypass self.post because data argument is needed in self.request and self.post use it as json
            response = self._client.request(
                "post",
                endpoint="sca/sca_scan_all/",
                files={"directory": tar_file},
                data={
                    "scan_parameters": SCAScanParameters.SCHEMA.dumps(scan_parameters)
                },
                extra_headers=extra_headers,
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_ok(response):
                result = SCAScanAllOutput.from_dict(response.json())
            else:
                result = load_detail(response)

            result.status_code = response.status_code

        return result

    def scan_diff(
        self,
        reference: bytes,
        current: bytes,
        scan_parameters: SCAScanParameters,
    ) -> Union[Detail, SCAScanDiffOutput]:
        result: Union[Detail, SCAScanDiffOutput]
        try:
            response = self._client.post(
                endpoint="sca/sca_scan_diff/",
                files={"reference": reference, "current": current},
                data={
                    "scan_parameters": SCAScanParameters.SCHEMA.dumps(scan_parameters)
                },
            )
        except requests.exceptions.ReadTimeout:
            result = Detail("The request timed out.")
            result.status_code = 504
        else:
            if is_ok(response):
                result = SCAScanDiffOutput.from_dict(response.json())
            else:
                result = load_detail(response)
            result.status_code = response.status_code
        return result
