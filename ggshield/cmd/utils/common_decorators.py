from functools import wraps
from typing import Callable, TypeVar

from typing_extensions import ParamSpec

from ggshield.core import ui
from ggshield.core.errors import handle_exception


T = TypeVar("T")
P = ParamSpec("P")


def exception_wrapper(func: Callable[P, int]) -> Callable[P, int]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> int:
        try:
            return func(*args, **kwargs)
        except Exception as error:
            return handle_exception(error)

    return wrapper


def display_beta_warning(func: Callable[P, T]) -> Callable[P, T]:
    """
    Displays warning about new verticals' commands being in beta.
    """

    @wraps(func)
    def func_with_beta_warning(*args: P.args, **kwargs: P.kwargs) -> T:
        ui.display_warning(
            "This feature is still in beta, its behavior may change in future versions."
        )
        return func(*args, **kwargs)

    return func_with_beta_warning
