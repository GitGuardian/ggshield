from copy import deepcopy
from operator import itemgetter
from pathlib import Path
from typing import Any, Dict

import yaml

from ggshield.cmd.main import cli
from tests.conftest import assert_invoke_ok


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
        "ignored-paths": [
            "**/snap*",
            "**/migrations/**/*",
            ".gitlab/*",
            "LICENSE",
        ],
        "show-secrets": True,
        "ignored-matches": [
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
        dct["secret"]["ignored-paths"] = sorted(dct["secret"]["ignored-paths"])
    except KeyError:
        pass
    try:
        dct["secret"]["ignored-matches"] = sorted(
            dct["secret"]["ignored-matches"], key=itemgetter("match")
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
