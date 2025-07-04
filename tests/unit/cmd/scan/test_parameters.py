from unittest.mock import Mock

import click
import pytest

from ggshield.cmd.secret.scan.secret_scan_common_options import _source_uuid_callback


class TestSourceUuidCallback:
    def test_invalid_uuid_raises_bad_parameter(self):
        """
        GIVEN an invalid UUID string
        WHEN calling _source_uuid_callback
        THEN it should raise click.BadParameter with the correct message
        """
        ctx = Mock()
        param = Mock()
        invalid_uuid = "not-a-valid-uuid"

        with pytest.raises(click.BadParameter) as exc_info:
            _source_uuid_callback(ctx, param, invalid_uuid)

        assert "source-uuid must be a valid UUID" in str(exc_info.value)
