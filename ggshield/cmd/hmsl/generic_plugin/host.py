import itertools

import hookspecs
import lib

import pluggy

from ggshield.cmd.hmsl.hmsl_utils import check_secrets
from ggshield.core.text_utils import display_info
from ggshield.verticals.hmsl.collection import prepare


def main(**kwargs):
    pm = get_plugin_manager()
    plugin = HmslPlugin(pm.hook)
    collected_secrets = plugin.collect_secrets(**kwargs)
    # full_hashes is True because we need the hashes to decrypt the secrets.
    # They will correctly be truncated by our client later.
    prepared_secrets = prepare(collected_secrets, naming_strategy, full_hashes=True)
    display_info(f"Collected {len(prepared_secrets.payload)} secrets.")
    check_secrets(
        ctx=ctx,
        prepared_secrets=prepared_secrets,
        json_output=True,
        full_hashes=True,
    )
    return 0


def get_plugin_manager():
    pm = pluggy.PluginManager("hmsl_check")
    pm.add_hookspecs(hookspecs)
    pm.load_setuptools_entrypoints("hmsl_check")
    pm.register(lib)
    return pm


class HmslPlugin:
    def __init__(self, hook):
        self.hook = hook

    @classmethod
    def cmd_options(cls, self):
        results = self.hook.cmd_options()
        return list(itertools.chain(*results))

    def collect_secrets(self, **_):
        results = self.hook.collect_secrets(**_)
        return list(itertools.chain(*results))

if __name__ == "__main__":
    main()