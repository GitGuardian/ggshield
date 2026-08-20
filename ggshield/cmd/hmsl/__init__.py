from typing import Any, List

import click

from ggshield.cmd.hmsl.api_status import status_cmd
from ggshield.cmd.hmsl.check import check_cmd
from ggshield.cmd.hmsl.check_secret_manager import check_secret_manager_group
from ggshield.cmd.hmsl.decrypt import decrypt_cmd
from ggshield.cmd.hmsl.fingerprint import fingerprint_cmd
from ggshield.cmd.hmsl.query import query_cmd
from ggshield.cmd.hmsl.quota import quota_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.lazy_group import PluginAwareLazyGroup


class _NaturalOrderPluginGroup(PluginAwareLazyGroup):
    """Plugin-aware (see PluginAwareLazyGroup) but keeps the declaration order of
    the commands in `--help`, like NaturalOrderGroup."""

    def list_commands(self, ctx: click.Context) -> List[str]:
        self._ensure_plugins()
        return list(self.commands)


@click.group(
    cls=_NaturalOrderPluginGroup,
    plugin_scope="hmsl",
    commands={
        "check": check_cmd,
        "check-secret-manager": check_secret_manager_group,
        "fingerprint": fingerprint_cmd,
        "query": query_cmd,
        "decrypt": decrypt_cmd,
        "quota": quota_cmd,
        "api-status": status_cmd,
    },
)
@add_common_options()
def hmsl_group(**kwargs: Any) -> None:
    """Commands for HasMySecretLeaked."""
