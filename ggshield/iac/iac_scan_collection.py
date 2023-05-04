from typing import Optional

from pygitguardian.iac_models import IaCScanResult


class IaCScanCollection:
    # TODO: It may be possible to get rid of this class and just use IaCScanResult
    id: str
    type: str
    # Can be None if the scan failed
    result: Optional[IaCScanResult]

    def __init__(
        self,
        id: str,
        type: str,
        result: Optional[IaCScanResult],
    ):
        self.id = id
        self.type = type
        self.result = result
