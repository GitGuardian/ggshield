import sys as _sys


__version__ = "1.53.0"

_MIN_PYTHON = (3, 9)


# Runs on the (possibly pre-3.9) interpreter itself, so it must avoid 3.7+ syntax
# (f-strings, evaluated annotations) or it crashes before explaining why.
def _ensure_supported_python(
    version_info: "tuple[int, ...]" = _sys.version_info[:2],
) -> None:
    if tuple(version_info[:2]) < _MIN_PYTHON:
        _sys.stderr.write(
            "ggshield requires Python %d.%d or newer, but it is running on "
            "Python %d.%d.\n"
            "Reinstall it on a supported interpreter, for example:\n"
            "    uv tool install --python 3.12 ggshield\n"
            "    pipx install --python 3.12 ggshield\n"
            % (_MIN_PYTHON[0], _MIN_PYTHON[1], version_info[0], version_info[1])
        )
        raise SystemExit(1)


_ensure_supported_python()
