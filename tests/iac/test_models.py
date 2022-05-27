import pytest

from ggshield.iac.models import IaCScanResult, IaCScanResultSchema
from ggshield.iac.models.iac_scan_parameters import (
    IaCScanParameters,
    IaCScanParametersSchema,
)


class TestModel:
    @pytest.mark.parametrize(
        "schema_klass, expected_klass, instance_data",
        [
            (
                IaCScanResultSchema,
                IaCScanResult,
                {
                    "id": "myid",
                    "type": "type",
                    "iac_engine_version": "version",
                    "entities_with_incidents": [
                        {
                            "filename": "myfilename",
                            "policy": "mypolicy,",
                            "policy_id": "mypolicyid",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "mydescription",
                            "documentation_url": "mydoc",
                            "component": "mycomponent",
                            "severity": "myseverity",
                            "ignore_sha": "mysha",
                            "some_extra_field": "extra",
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
