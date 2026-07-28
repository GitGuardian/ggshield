from copy import deepcopy
from operator import itemgetter
from pathlib import Path
from typing import Any, Dict

import yaml

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


V1_CONFIG_CONTENT = """
paths-ignore:
  - '**/migrations/**/*'
  - '**/snap*'
  - '.gitlab/*'
  - 'LICENSE'

matches-ignore:
  - name:
    match: vLXyx1iAhFo2xgb71tTa
  - name: generic password
    match: 05Panda_8463
  - name: test github oauth password
    match: 29825c15f543be6158140d0561a2257a5157ee6d845355c62eb1b53bfd4155af
  - v1.6793be7966338465559c751561e82de746880ccb

all-policies: true
show-secrets: true
"""

V2_CONFIG_DICT = {
    "version": 2,
    "secret": {
        "ignored_paths": [
            "**/snap*",
            "**/migrations/**/*",
            ".gitlab/*",
            "LICENSE",
        ],
        "show_secrets": True,
        "ignored_matches": [
            {"name": "", "match": "vLXyx1iAhFo2xgb71tTa"},
            {"name": "generic password", "match": "05Panda_8463"},
            {
                "name": "test github oauth password",
                "match": "29825c15f543be6158140d0561a2257a5157ee6d845355c62eb1b53bfd4155af",
            },
            {"name": "", "match": "v1.6793be7966338465559c751561e82de746880ccb"},
        ],
    },
}


def normalize_config_dict(dct: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sort lists inside a config dict so that the dicts can be compared with ==
    """
    dct = deepcopy(dct)
    try:
        dct["secret"]["ignored_paths"] = sorted(dct["secret"]["ignored_paths"])
    except KeyError:
        pass
    try:
        dct["secret"]["ignored_matches"] = sorted(
            dct["secret"]["ignored_matches"], key=itemgetter("match")
        )
    except KeyError:
        pass
    return dct


def test_config_migrate_cmd(cli_fs_runner):
    """
    GIVEN a v1 config file
    WHEN `ggshield config migrate` is called
    THEN the file is migrated to v2
    AND the v1 config file is kept as a backup
    """
    config_path = Path(".gitguardian.yaml")
    config_path.write_text(V1_CONFIG_CONTENT)

    result = cli_fs_runner.invoke(cli, ["config", "migrate"])
    assert_invoke_ok(result)

    # Check new file is v2
    with config_path.open() as f:
        dct = yaml.safe_load(f)
    assert normalize_config_dict(dct) == normalize_config_dict(V2_CONFIG_DICT)

    # Check backup is unchanged
    assert ".gitguardian.yaml.old" in result.stdout
    assert Path(".gitguardian.yaml.old").read_text() == V1_CONFIG_CONTENT


def test_config_migrate_cmd_no_config_file(cli_fs_runner):
    """
    GIVEN no configuration file in the current directory
    WHEN `ggshield config migrate` is called
    THEN it fails with an actionable error message
    """
    result = cli_fs_runner.invoke(cli, ["config", "migrate"])

    assert_invoke_exited_with(result, 128)
    assert "No configuration file found" in result.output
    assert "--config-path" in result.output


def test_config_migrate_cmd_with_config_path(cli_fs_runner):
    """
    GIVEN a v1 config file in another directory
    WHEN `ggshield config migrate` is called with `--config-path`
    THEN the file is migrated regardless of the current directory
    """
    config_path = Path("subdir") / ".gitguardian.yaml"
    config_path.parent.mkdir()
    config_path.write_text(V1_CONFIG_CONTENT)

    result = cli_fs_runner.invoke(
        cli, ["--config-path", str(config_path), "config", "migrate"]
    )
    assert_invoke_ok(result)

    with config_path.open() as f:
        dct = yaml.safe_load(f)
    assert normalize_config_dict(dct) == normalize_config_dict(V2_CONFIG_DICT)
    assert Path("subdir/.gitguardian.yaml.old").read_text() == V1_CONFIG_CONTENT
