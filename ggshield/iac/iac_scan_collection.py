from typing import Optional

from pygitguardian.iac_models import IaCScanResult


class IaCScanCollection:
    id: str
    type: str
    iac_result: Optional[IaCScanResult] = None

    def __init__(
        self,
        id: str,
        type: str,
        iac_result: Optional[IaCScanResult] = None,
    ):
        self.id = id
        self.type = type
        self.iac_result = iac_result

    @property
    def has_iac_result(self) -> bool:
        return bool(self.iac_result and self.iac_result.entities_with_incidents)
