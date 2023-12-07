from functools import wraps
from typing import Callable, TypeVar

import click
from typing_extensions import ParamSpec

from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.errors import handle_exception
from ggshield.core.text_utils import display_warning


T = TypeVar("T")
P = ParamSpec("P")


def exception_wrapper(func: Callable[P, int]) -> Callable[P, int]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> int:
        try:
            return func(*args, **kwargs)
        except Exception as error:
            ctx = next(arg for arg in args if isinstance(arg, click.Context))
            config = ContextObj.get(ctx).config
            return handle_exception(error, config.user_config.verbose)

    return wrapper


def display_beta_warning(func: Callable[P, T]) -> Callable[P, T]:
    """
    Displays warning about new verticals' commands being in beta.
    """

    @wraps(func)
    def func_with_beta_warning(*args: P.args, **kwargs: P.kwargs) -> T:
        display_warning(
            "This feature is still in beta, its behavior may change in future versions."
        )
        return func(*args, **kwargs)

    return func_with_beta_warning
