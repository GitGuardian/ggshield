from functools import wraps

import click

from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.core.text_utils import display_warning


def exception_wrapper(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as error:
            ctx = next(arg for arg in args if isinstance(arg, click.Context))
            config: Config = ctx.obj["config"]
            return handle_exception(error, config.user_config.verbose)

    return wrapper


def display_beta_warning(func):
    """
    Displays warning about new verticals' commands being in beta.
    """

    @wraps(func)
    def func_with_beta_warning(*args, **kwargs):
        display_warning(
            "This feature is still in beta, its behavior may change in future versions."
        )
        return func(*args, **kwargs)

    return func_with_beta_warning
