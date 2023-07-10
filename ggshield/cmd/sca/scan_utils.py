from typing import Type

import click

from ggshield.cmd.common_options import use_json
from ggshield.core.config import Config
from ggshield.sca.output import SCAOutputHandler, SCATextOutputHandler


def create_output_handler(ctx: click.Context) -> SCAOutputHandler:
    """Read objects defined in ctx.obj and create the appropriate OutputHandler
    instance"""
    output_handler_cls: Type[SCAOutputHandler]
    if use_json(ctx):
        raise NotImplementedError(
            "JSON output is not currently supported for SCA scan."
        )
    else:
        output_handler_cls = SCATextOutputHandler
    config: Config = ctx.obj["config"]
    return output_handler_cls(verbose=config.user_config.verbose)
