import codecs
import logging
import urllib.parse
from abc import ABC, abstractmethod
from io import SEEK_END, SEEK_SET
from pathlib import Path
from typing import BinaryIO, Optional, Tuple

import charset_normalizer
from charset_normalizer import CharsetMatch

from ggshield.utils.git_shell import Filemode


logger = logging.getLogger(__name__)


# Our worse encoding (UTF-32) would take 4 bytes to encode ASCII, where UTF-8 would take
# only 1. If the file is longer than byte_size / UTF8_TO_WORSE_OTHER_ENCODING_RATIO, no
# need to look into it: it's too big.
UTF8_TO_WORSE_OTHER_ENCODING_RATIO = 4


class DecodeError(Exception):
    """
    Raised when a Scannable cannot determine the encoding of its content.

    Similar to UnicodeDecodeError, but easier to instantiate.
    """

    pass


class NonSeekableFileError(Exception):
    """Raised when a file cannot be seeked"""

    pass


class Scannable(ABC):
    """Base class for content that can be scanned by GGShield"""

    def __init__(self, filemode: Filemode = Filemode.FILE):
        self.filemode = filemode
        self._content: Optional[str] = None
        self._utf8_encoded_size: Optional[int] = None

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
    def is_longer_than(self, max_utf8_encoded_size: int) -> bool:
        """Return true if the length of the *utf-8 encoded* content is greater than
        `max_utf8_encoded_size`.
        When possible, implementations must try to answer this without reading all
        content.
        Raise `DecodeError` if the content cannot be decoded.
        """
        raise NotImplementedError

    @abstractmethod
    def _read_content(self) -> None:
        """Read the content of the scannable  if necessary, store it in `self._content`
        and the UTF8 encoded size in `self._utf8_encoded_size`"""
        raise NotImplementedError

    @property
    def content(self) -> str:
        """Return the decoded content of the scannable"""
        if self._content is None:
            self._read_content()
            if self._content is None:
                raise ValueError("content is None after reading")
        return self._content

    @property
    def utf8_encoded_size(self) -> int:
        if self._utf8_encoded_size is None:
            self._read_content()
            if self._utf8_encoded_size is None:
                raise ValueError("utf8_encoded_size is None after reading")
        return self._utf8_encoded_size

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} url={self.url} filemode={self.filemode}>"

    @staticmethod
    def _decode_bytes(
        raw_document: bytes, charset_match: Optional[CharsetMatch] = None
    ) -> Tuple[str, int]:
        """Low level helper function to decode bytes using `charset_match`. If
        `charset_match` is not provided, tries to determine it itself.

        Returns a tuple of (decoded_content, utf8_encoded_size).

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
        content = raw_document.decode(charset_match.encoding, errors="replace")

        if charset_match.encoding in {"utf_8", "ascii"}:
            # The document is already in UTF-8, no need to encode it as UTF-8 to
            # determine UTF-8 encoded size.
            utf8_encoded_size = len(raw_document)
        else:
            utf8_encoded_size = len(content.encode(errors="replace"))

        return content, utf8_encoded_size

    @staticmethod
    def _is_file_longer_than(
        fp: BinaryIO, max_utf8_encoded_size: int
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """Helper function to implement is_longer_than() for file-based Scannable classes.

        Returns a tuple of:
        - True if file is longer than `size`, False otherwise
        - The decoded content as a string if the file has been fully read, None otherwise
        - The utf8-encoded size if we know it, None otherwise

        Raises DecodeError if the file cannot be decoded.
        """
        # Get the byte size
        # Note: IOBase.seekable() returns True on some non-seekable files like /proc/self/mounts
        try:
            byte_size = fp.seek(0, SEEK_END)
            fp.seek(0, SEEK_SET)
        except OSError as exc:
            raise NonSeekableFileError() from exc

        if byte_size > max_utf8_encoded_size * UTF8_TO_WORSE_OTHER_ENCODING_RATIO:
            # Even if the file used the worst encoding (UTF-32), encoding the content of
            # this file as UTF-8 would produce a file longer than
            # `max_utf8_encoded_size`, so bail out
            return True, None, None

        # Determine the encoding
        charset_matches = charset_normalizer.from_fp(fp)
        charset_match = charset_matches.best()
        if charset_match is None:
            raise DecodeError

        logger.debug('filename="%s" charset=%s', fp.name, charset_match.encoding)
        if charset_match.encoding in {"utf_8", "ascii"}:
            # Shortcut: the content is already in UTF-8 (or ASCII, which is a subset of
            # utf-8), no need to decode anything
            return byte_size > max_utf8_encoded_size, None, byte_size

        # We can't know if the file is longer without reading its content, do it now
        fp.seek(0, SEEK_SET)
        content, utf8_encoded_size = Scannable._decode_bytes(fp.read(), charset_match)
        logger.debug('filename="%s" utf8_encoded_size=%d', fp.name, utf8_encoded_size)
        if utf8_encoded_size > max_utf8_encoded_size:
            return True, None, utf8_encoded_size
        else:
            # We read the whole file, keep it
            return False, content, utf8_encoded_size


class StringScannable(Scannable):
    """Implementation of Scannable for content already loaded in memory"""

    def __init__(self, url: str, content: str, filemode: Filemode = Filemode.FILE):
        super().__init__(filemode)
        self._url = url
        self._path: Optional[Path] = None
        self._content = content

    def _read_content(self) -> None:
        assert self._content is not None
        if self._utf8_encoded_size is None:
            self._utf8_encoded_size = len(self._content.encode(errors="replace"))

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

    def is_longer_than(self, max_utf8_encoded_size: int) -> bool:
        self._read_content()
        assert self._utf8_encoded_size is not None
        return self._utf8_encoded_size > max_utf8_encoded_size
