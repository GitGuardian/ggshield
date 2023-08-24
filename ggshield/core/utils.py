
from datetime import datetime
from itertools import islice
from typing import Iterable, List, TypeVar


def datetime_from_isoformat(text: str) -> datetime:
    """Work around for datetime.isoformat() not supporting ISO dates ending with Z"""
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


T = TypeVar("T")


def batched(iterable: Iterable[T], batch_size: int) -> Iterable[List[T]]:
    it = iter(iterable)
    while True:
        batch = list(islice(it, batch_size))
        if batch:
            yield batch
        else:
            return
