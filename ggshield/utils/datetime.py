from datetime import datetime


def datetime_from_isoformat(text: str) -> datetime:
    """Work around for datetime.isoformat() not supporting ISO dates ending with Z"""
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def get_pretty_date(dt: datetime) -> str:
    """
    convert the given datetime to the format September 1, 2022
    """
    # Don't use %d for the day because it adds a leading 0
    return dt.strftime(f"%B {dt.day}, %Y")
