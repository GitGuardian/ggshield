import pluggy

from typing import Iterator

from ggshield.verticals.hmsl.collection import SecretWithKey

hookspec = pluggy.HookspecMarker("hmsl_check")


@hookspec
def cmd_options():
    """
    Specifies the available command options via click
    """


@hookspec
def collect_secrets(**_) -> Iterator[SecretWithKey]:
    """
    Collects the secrets in a given scope
    """


