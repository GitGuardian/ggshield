from ggshield.core.text_utils import STYLE, format_text, pluralize


def clip_long_line(
    content: str,
    max_length: int,
    before: bool = False,
    after: bool = False,
    min_length: int = 10,
) -> str:
    """
    Add a "…" character before and/or after the given string
    if it exceeds a maximum length.
    """
    ellipsis = "…"
    content_length = len(content)
    if content_length > max_length:
        if before and after and content_length > max_length + 1:
            content = (
                ellipsis
                + content[
                    (content_length - max(max_length, min_length)) // 2
                    + 1 : (content_length + max(max_length, min_length)) // 2
                    - 1
                ]
                + ellipsis
            )
        elif after:
            content = content[: max(max_length - 1, min_length)] + ellipsis
        elif before:
            content = ellipsis + content[min(-max_length + 1, -min_length) :]
    return content


def file_info(filename: str, nb_secrets: int) -> str:
    """Return the formatted file info (number of secrets + filename)."""
    return "\n{} {}: {} {} detected\n".format(
        format_text(">", STYLE["detector_line_start"]),
        format_text(filename, STYLE["filename"]),
        nb_secrets,
        pluralize("incident", nb_secrets, "incidents"),
    )
