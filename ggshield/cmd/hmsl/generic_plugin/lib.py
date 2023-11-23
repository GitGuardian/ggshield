import json
from subprocess import run
from typing import Iterator

import click
import hmsl_check

from ggshield.cmd.hmsl.hmsl_common_options import (
    input_arg,
)
from ggshield.verticals.hmsl.collection import (
    SecretWithKey,
)


@hmsl_check.hookimpl
def cmd_options():
    return [
        input_arg,
        click.option(
            "--args",
            "args",
            default="",
            required=False,
            type=str,
            help="Command options.",
        )
    ]


@hmsl_check.hookimpl
def collect_secrets(ctx: click.Context, path: str, args: str, **_) -> Iterator[SecretWithKey]:
    args = [arg for arg in args.split(' ') if arg]
    res = run([path, *args], capture_output=True)
    if res.returncode != 0:
        raise Exception(res.stderr.decode('utf-8'))
    for secret in json.loads(res.stdout.decode('utf-8')):
        yield SecretWithKey(key=secret.get("key"), value=secret["value"])