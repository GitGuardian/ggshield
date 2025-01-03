from functools import wraps
from typing import Callable, TypeVar

from typing_extensions import ParamSpec

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
