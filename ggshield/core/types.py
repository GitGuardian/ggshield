# This file exists to avoid circular dependencies when import config
from typing import Dict


"""An ignored match is a dict of the form {"name": some_name, "match": SHA}
"""
IgnoredMatch = Dict[str, str]
