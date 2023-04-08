import codecs
import logging
import urllib.parse
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO, Callable, List, Optional, Tuple

import charset_normalizer
from charset_normalizer import CharsetMatch

from ggshield.core.utils import Filemode


logger = logging.getLogger(__name__)


class DecodeError(Exception):
    """
    Raised when a Scannable cannot determine the encoding of its content.

    Similar to UnicodeDecodeError, but easier to instantiate.
    """

    pass


class Scannable(ABC):
    """Base class for content that can be scanned by GGShield"""

    def __init__(self, filemode: Filemode = Filemode.FILE):
        self.filemode = filemode

    @property
    @abstractmethod
    def url(self) -> str:
        """Act as a unique identifier for the Scannable. May use custom protocols if
        required."""
        raise NotImplementedError

    @property
    @abstractmethod
    def filename(self) -> str:
        """To avoid breakage with the rest of the code base, implementations currently
        return the URL or path of the instance for now, but it should really return
        just the filename, or be removed."""
        # TODO: make this really return the filename, or remove it
        raise NotImplementedError

    @property
    @abstractmethod
    def path(self) -> Path:
        raise NotImplementedError

    @abstractmethod
    def is_longer_than(self, size: int) -> bool:
        """Return true if the length of the *decoded* content is greater than `size`.
        When possible, implementations must try to answer this without reading all
        content.
        Raise `DecodeError` if the content cannot be decoded.
        """
        raise NotImplementedError

    @property
    @abstractmethod
    def content(self) -> str:
        """Return the decoded content of the scannable"""
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} url={self.url} filemode={self.filemode}>"

    @staticmethod
    def _decode_bytes(
        raw_document: bytes, charset_match: Optional[CharsetMatch] = None
    ) -> str:
        """Low level helper function to decode bytes using `charset_match`. If
        `charset_match` is not provided, tries to determine it itself.

        Raises DecodeError if the document cannot be decoded."""
        if charset_match is None:
            charset_match = charset_normalizer.from_bytes(raw_document).best()
            if charset_match is None:
                # This means we were not able to detect the encoding
                raise DecodeError

        # Special case for utf_8 + BOM: `bytes.decode()` does not skip the BOM, so do it
        # ourselves
        if charset_match.encoding == "utf_8" and raw_document.startswith(
            codecs.BOM_UTF8
        ):
            raw_document = raw_document[len(codecs.BOM_UTF8) :]
        return raw_document.decode(charset_match.encoding, errors="replace")

    @staticmethod
    def _is_file_longer_than(fp: BinaryIO, size: int) -> Tuple[bool, Optional[str]]:
        """Helper function to implement is_longer_than() for file-based Scannable classes.

        Returns a tuple of:
        - True if file is longer than `size`, False otherwise
        - The decoded content as a string, if it has been fully read, None otherwise

        Raises DecodeError if the file cannot be decoded.
        """
        byte_content = b""
        str_content = ""

        charset_matches = charset_normalizer.from_fp(fp)
        charset_match = charset_matches.best()
        if charset_match is None:
            raise DecodeError
        fp.seek(0)
        while True:
            # Try to read more than the requested size:
            # - If the file is smaller, that changes nothing
            # - if the file is bigger, we potentially avoid a second read
            byte_chunk = fp.read(size * 2)
            if byte_chunk:
                byte_content += byte_chunk
                # Note: we decode `byte_content` and not `byte_chunk`: we can't
                # decode just the chunk because we have no way to know if it starts
                # and ends at complete code-point boundaries
                str_content = Scannable._decode_bytes(byte_content, charset_match)
                if len(str_content) > size:
                    return True, None
            else:
                # We read the whole file, keep it
                return False, str_content


class StringScannable(Scannable):
    """Implementation of Scannable for content already loaded in memory"""

    def __init__(self, url: str, content: str, filemode: Filemode = Filemode.FILE):
        super().__init__(filemode)
        self._url = url
        self._path: Optional[Path] = None
        self._content = content

    @property
    def url(self) -> str:
        return self._url

    @property
    def filename(self) -> str:
        return str(self._url)

    @property
    def path(self) -> Path:
        if self._path is None:
            result = urllib.parse.urlparse(self._url)
            self._path = Path(result.path)
        return self._path

    def is_longer_than(self, size: int) -> bool:
        return len(self._content) > size

    @property
    def content(self) -> str:
        return self._content


class Files:
    """
    Files is a list of files. Useful for directory scanning.

    TODO: Rename to something like ScannableCollection: this class is no longer limited
    to holding File instances.
    """

    def __init__(self, files: List[Scannable]):
        self._files = files

    @property
    def files(self) -> List[Scannable]:
        """The list of files owned by this instance. The same filename can appear twice,
        in case of a merge commit."""
        return self._files

    @property
    def paths(self) -> List[Path]:
        """Convenience property to list paths in the same order as files"""
        return [x.path for x in self.files]

    def __repr__(self) -> str:
        return f"<Files files={self.files}>"

    def apply_filter(self, filter_func: Callable[[Scannable], bool]) -> "Files":
        return Files([file for file in self.files if filter_func(file)])
