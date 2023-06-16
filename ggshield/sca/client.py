from dataclasses import dataclass
from typing import Dict, List, Optional, Union, cast

import marshmallow_dataclass
from pygitguardian.client import GGClient, is_ok, load_detail
from pygitguardian.models import Base, BaseSchema, Detail, FromDictMixin


@dataclass
class ComputeSCAFilesResult(Base, FromDictMixin):
    sca_files = List[str]
    potential_siblings = List[str]


ComputeSCAFilesResult.SCHEMA = cast(
    BaseSchema,
    marshmallow_dataclass.class_schema(ComputeSCAFilesResult, base_schema=BaseSchema)(),
)


class SCAClient:
    def __init__(self, client: GGClient):
        self._client = client

    def compute_sca_files(
        self,
        touched_files: List[str],
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Union[Detail, ComputeSCAFilesResult]:
        response = self._client.get(
            endpoint="compute_sca_files",
            params={"touched_files": touched_files},
            extra_headers=extra_headers,
        )
        result: Union[Detail, ComputeSCAFilesResult]
        if is_ok(response):
            result = response.json()
        else:
            result = load_detail(response)

        result.status_code = response.status_code
        return result
