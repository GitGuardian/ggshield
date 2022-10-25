import re


POLICY_ID_PATTERN = re.compile("GG_IAC_[0-9]{4}")


def validate_policy_id(policy_id: str) -> bool:
    return bool(POLICY_ID_PATTERN.fullmatch(policy_id))
