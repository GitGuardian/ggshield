import pytest

from ggshield.iac.models import (
    IaCMatch,
    IaCMatchSchema,
    IaCPolicyBreak,
    IaCPolicyBreakSchema,
    IaCScanResult,
    IaCScanResultSchema,
)
from ggshield.iac.models.iac_multi_scan_result import (
    IaCMultiScanResult,
    IaCMultiScanResultSchema,
)
from ggshield.iac.models.iac_scan_parameters import (
    IaCScanParameters,
    IaCScanParametersSchema,
)


class TestModel:
    @pytest.mark.parametrize(
        "schema_klass, expected_klass, instance_data",
        [
            (
                IaCMatchSchema,
                IaCMatch,
                {"filename": "hello", "match": "hello", "type": "hello"},
            ),
            (
                IaCPolicyBreakSchema,
                IaCPolicyBreak,
                {
                    "type": "hello",
                    "policy": "hello",
                    "validity": "hey",
                    "matches": [
                        {"filename": "hello", "match": "hello", "type": "hello"}
                    ],
                    "policy_details": {},
                    "ignore_sha": "hello",
                },
            ),
            (
                IaCScanResultSchema,
                IaCScanResult,
                {
                    "policy_break_count": 1,
                    "policies": ["pol"],
                    "policy_breaks": [
                        {
                            "type": "break",
                            "policy": "mypol",
                            "matches": [
                                {
                                    "filename": "hello",
                                    "match": "hello",
                                    "type": "hello",
                                }
                            ],
                            "policy_details": {},
                            "ignore_sha": "hello",
                        }
                    ],
                },
            ),
            (
                IaCMultiScanResultSchema,
                IaCMultiScanResult,
                {
                    "scan_results": [
                        {
                            "policy_break_count": 1,
                            "policies": ["pol"],
                            "policy_breaks": [
                                {
                                    "type": "break",
                                    "policy": "mypol",
                                    "matches": [
                                        {
                                            "filename": "hello",
                                            "match": "hello",
                                            "type": "hello",
                                        }
                                    ],
                                    "policy_details": {},
                                    "ignore_sha": "hello",
                                }
                            ],
                        }
                    ],
                },
            ),
            (
                IaCScanParametersSchema,
                IaCScanParameters,
                {"ignored_policies": ["pol1", "pol2"], "minimum_severity": "LOW"},
            ),
        ],
    )
    def test_schema_loads(self, schema_klass, expected_klass, instance_data):
        """
        GIVEN the right kwargs and an extra field in dict format
        WHEN loading using the schema
        THEN the extra field is not taken into account
            AND the result should be an instance of the expected class
        """
        schema = schema_klass()

        data = {**instance_data, "field": "extra"}

        obj = schema.load(data)
        assert isinstance(obj, expected_klass)
