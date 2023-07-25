import re


GHSA_ID_PATTERN = re.compile("GHSA(-[a-zA-Z0-9]{4}){3}")


def is_ghsa_valid(ghsa_id: str) -> bool:
    return bool(GHSA_ID_PATTERN.fullmatch(ghsa_id))
