class VaultCliTokenFetchingError(Exception):
    """Raised when the token used by Vault CLI cannot be fetched."""

    pass


class VaultInvalidUrlError(Exception):
    """Raised when the Vault instance URL cannot be parsed."""

    pass


class VaultPathIsNotADirectoryError(Exception):
    """Raised when list_kv_items was called on a file and not a directory."""

    pass


class VaultNotFoundItemError(Exception):
    """Raised when list_kv_items was called on a directory and not a file."""

    pass


class VaultForbiddenItemError(Exception):
    """Raised when a 403 forbidden error was returned for an item."""

    pass
