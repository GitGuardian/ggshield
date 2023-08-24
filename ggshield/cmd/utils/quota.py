from ggshield.core.text_utils import format_text


def format_quota_color(remaining: int, limit: int) -> str:
    if limit == 0:
        return format_text(str(remaining), {"fg": "white"})

    available_percent = remaining / limit
    if available_percent < 0.25:
        color = "red"
    elif available_percent < 0.75:
        color = "yellow"
    else:
        color = "green"

    return format_text(str(remaining), {"fg": color})
