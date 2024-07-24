import textwrap


def pad_text(text: str, padding: str = "  "):
    return textwrap.indent(text, padding)
