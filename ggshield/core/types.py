# This file exists to avoid circular dependencies when import config
from typing import Dict, Optional


"""An ignored match is a dict of the form {"name": some_name, "match": SHA}

This is a hack. It should be turned into a dataclass. This would provide more type
safety and should remove the need for the post_init_ignored_match() function.
"""
IgnoredMatch = Dict[str, Optional[str]]


def post_init_ignored_match(match: IgnoredMatch) -> None:
    if match["name"] is None:
        match["name"] = ""
