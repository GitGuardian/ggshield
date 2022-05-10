from datetime import datetime, timezone
from typing import Tuple

import pytest

from ggshield.cmd.main import cli
from ggshield.core.config import Config

from .utils import prepare_config


DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"

EXPECTED_OUTPUT = """[https://dashboard.gitguardian.com]
default_token_lifetime: None
workspace_id: 1
url: https://dashboard.gitguardian.com
token: some token
token_name: some token name
expiry: 2022-05-04T17:00:00Z

[https://some-gg-instance.com]
default_token_lifetime: None
workspace_id: 1
url: https://some-gg-instance.com
token: some token
token_name: first token
expiry: 2022-05-04T17:00:00Z

[https://some-gg-instance.com]
default_token_lifetime: None
workspace_id: not set
url: https://some-gg-instance.com
token: not set
token_name: not set
expiry: not set
"""


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "ggshield.core.config.get_auth_config_dir", lambda: str(tmp_path)
    )


class TestAuthConfigList:
    def test_valid_list(self, cli_fs_runner):
        """
        GIVEN several auth config saved
        WHEN calling ggshield auth config list command
        THEN all config should be listed with the correct format
        """

        # May 4th
        some_date = datetime(2022, 5, 4, 17, 0, 0, 0, tzinfo=timezone.utc)

        prepare_config(expiry_date=some_date)
        prepare_config(
            instance_url="https://some-gg-instance.com",
            token="first_token",
            token_name="first token",
            expiry_date=some_date,
        )
        prepare_config(
            instance_url="https://some-gg-instance.com",
            with_account=False,
            expiry_date=some_date,
        )

        exit_code, output = self.run_cmd(cli_fs_runner)

        assert exit_code == 0, output
        assert output == EXPECTED_OUTPUT

    @staticmethod
    def run_cmd(cli_fs_runner) -> Tuple[bool, str]:
        cmd = ["config", "list"]
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output
