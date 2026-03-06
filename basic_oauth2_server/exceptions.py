"""Contains exceptions this application raises."""


class OAuth2Exception(Exception):
    """Base class for all OAuth2 exceptions.

    OAuth2 usually serializes a "error" and "error_description" in the response body, so these are included as attributes.
    """

    def __init__(self, error: str, description: str | None = None):
        super().__init__(description)
        self.error = error
        self.description = description


class InvalidClientException(OAuth2Exception):
    """Raised when client authentication fails.

    Usually when the client id is invalid, or the client secret is invalid.
    """

    def __init__(self, description: str | None = None):
        super().__init__("invalid_client", description)


class InvalidScopeException(OAuth2Exception):
    """Raised when requested scopes are invalid.

    The scopes can be invalid because they are not set up in the client model being used, or because they are not valid scopes at all.
    """

    def __init__(self, description: str | None = None):
        super().__init__("invalid_scope", description)


class InvalidAudienceException(OAuth2Exception):
    """Raised when requested audience is invalid.

    The audience can be invalid because it is not set up in the client model being used.
    """

    def __init__(self, description: str | None = None):
        super().__init__("invalid_audience", description)


class InvalidGrantException(OAuth2Exception):
    """Raised when the provided grant is invalid

    The grant can not be handled by our application either because it is not implemented, or because it is invalid in this context.
    """

    def __init__(self, description: str | None = None):
        super().__init__("invalid_grant", description)


class ServerErrorException(OAuth2Exception):
    """Raised when an unexpected error occurs on the server."""

    def __init__(self, description: str | None = None):
        super().__init__("server_error", description)
