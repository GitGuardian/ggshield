from itertools import islice
from typing import Iterable, List, TypeVar


T = TypeVar("T")


def batched(iterable: Iterable[T], batch_size: int) -> Iterable[List[T]]:
    # This function is a backport of the itertools.batched() function  from Python 3.12
    it = iter(iterable)
    while True:
        batch = list(islice(it, batch_size))
        if batch:
            yield batch
        else:
            return
