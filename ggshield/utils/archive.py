import shutil
import stat
import tarfile
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Tuple
from zipfile import ZipFile, ZipInfo


class UnsafeArchive(Exception):
    """
    Raised when an archive is considered unsafe.

    An archive is considered unsafe if it contains paths outside the extract directory
    or symbolic links pointing outside the extract directory.
    """

    def __init__(self):
        self.bad_paths: List[Path] = []
        self.bad_links: List[Tuple[Path, Path]] = []

    def __str__(self) -> str:
        lines: List[str] = ["Archive contains unsafe files."]
        if self.bad_paths:
            lines.append("Paths outside the archive root:")
            lines.extend(f"- {p}" for p in self.bad_paths)
        if self.bad_links:
            lines.append("Links pointing outside the archive root:")
            lines.extend(f"- {src} -> {target}" for src, target in self.bad_links)
        return "\n".join(lines)

    def add_bad_path(self, path: Path) -> None:
        self.bad_paths.append(path)

    def add_bad_link(self, path: Path, target: Path) -> None:
        self.bad_links.append((path, target))

    def has_fails(self) -> bool:
        return bool(self.bad_paths) or bool(self.bad_links)


def safe_unpack(archive: Path, extract_dir: Path) -> None:
    """
    If `archive` is safe, extract it in `extract_dir`. Otherwise, raise `UnsafeArchive`.
    """
    check_archive_content(archive)

    # unpack_archive does not know .whl files are zip files
    archive_format = "zip" if archive.suffix in {".whl", ".jar"} else None

    shutil.unpack_archive(archive, extract_dir, format=archive_format)


def check_archive_content(archive: Path) -> None:
    """
    Check `archive` safety, raise `UnsafeArchive` if it is unsafe.
    """
    if archive.suffix in {".zip", ".whl", ".jar"}:
        _check_zip_content(archive)
    else:
        _check_tar_content(archive)


@lru_cache
def _archive_root():
    """
    Returns a fake archive root, used by _is_bad_path().
    Can be whatever we want except the root directory, otherwise we won't detect a path
    outside the archive root.
    """

    # The call to `resolve()` is required on Windows to include the drive letter.
    return Path("/some/dir").resolve()


def _is_bad_path(path: Path) -> bool:
    """
    Verify `path` is not outside the archive root.

    Good paths: `foo`, `foo/../bar`
    Bad paths: `../foo`, `foo/../../bar`, `/foo/bar`
    """

    root = _archive_root()

    # Code can be simplified to use Path.is_relative_to() when we move to Python 3.9
    try:
        root.joinpath(path).resolve().relative_to(root)
        return False
    except ValueError:
        return True


def _is_bad_link(link: Path, target: Path) -> bool:
    """
    Given a link pointing to a target, verify it does not point outside the archive
    root.

    Good link example:
        link="foo/link", target="../file"
        Points to "file" in the archive root.

    Bad link example:
        link="foo/link", target="../../file"
        Points to "file" in the directory above the archive root.

    Another bad link example:
        link="foo/link", target="/etc/passwd"
        Points to "/etc/passwd"
    """

    # Links are interpreted relative to the directory containing them, so we join
    # target to the link parent
    target = link.parent.joinpath(target)

    return _is_bad_path(target)


def _check_tar_content(archive: Path) -> None:
    # This exception is populated with bad paths or bad links if we find some. It's only
    # raised if we found some.
    unsafe_archive = UnsafeArchive()

    with tarfile.open(archive) as tf:
        for info in tf:
            path = Path(info.name)
            if _is_bad_path(path):
                unsafe_archive.add_bad_path(path)
            elif info.issym() or info.islnk():
                target = Path(info.linkname)
                if _is_bad_link(path, target):
                    unsafe_archive.add_bad_link(path, target)

    if unsafe_archive.has_fails():
        raise unsafe_archive


def _zip_get_symlink_target(zip: ZipFile, info: ZipInfo) -> Optional[Path]:
    """
    If `info` points to a symbolic link inside `zip`, then return the link target.
    If it's a regular file, return None.
    """
    if not stat.S_ISLNK(info.external_attr >> 16):
        return None
    target = zip.open(info).read().decode()
    return Path(target)


def _check_zip_content(archive: Path) -> None:
    # This exception is populated with bad paths or bad links if we find some. It's only
    # raised if we found some.
    unsafe_archive = UnsafeArchive()

    with ZipFile(archive) as zip:
        for info in zip.infolist():
            path = Path(info.filename)
            if target := _zip_get_symlink_target(zip, info):
                if _is_bad_link(path, target):
                    unsafe_archive.add_bad_link(path, target)
            elif _is_bad_path(path):
                unsafe_archive.add_bad_path(path)

    if unsafe_archive.has_fails():
        raise unsafe_archive
