import click


class AuthError(click.ClickException):
    """
    Base exception for Auth-related configuration error
    """

    def __init__(self, instance: str, message: str):
        super(AuthError, self).__init__(message)
        self.instance = instance


class UnknownInstanceError(AuthError):
    """
    Raised when the requested instance does not exist
    """

    def __init__(self, instance: str):
        super(UnknownInstanceError, self).__init__(
            instance, f"Unknown instance: '{instance}'"
        )


class AuthExpiredError(AuthError):
    """
    Raised when authentication has expired for the given instance
    """

    def __init__(self, instance: str):
        super(AuthExpiredError, self).__init__(
            instance,
            f"Instance '{instance}' authentication expired, please authenticate again.",
        )


class MissingTokenError(AuthError):
    def __init__(self, instance: str):
        super(MissingTokenError, self).__init__(
            instance, f"No token is saved for this instance: '{instance}'"
        )
