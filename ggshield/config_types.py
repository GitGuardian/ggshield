# This file exists to avoid circular dependencies when import config
from typing import Dict, Union


"""An ignored match can be either a string holding the SHA of the match, or a dict of the
form {"name": some_name, "match": SHA}
"""
IgnoredMatch = Union[str, Dict[str, str]]
