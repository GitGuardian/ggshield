from typing import List

import click


class NaturalOrderGroup(click.Group):
    """
    Helper class to force the order of the commands in the help text.
    Copied from https://github.com/pallets/click/issues/513#issuecomment-504158316
    This will not work with python < 3.6.
    """

    def list_commands(self, ctx: click.Context) -> List[str]:
        return list(self.commands.keys())
