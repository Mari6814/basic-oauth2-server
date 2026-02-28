"""Collection of various exceptions specific to this project."""

from typing import Literal


class OAuthException(Exception):
    """Base class for errors that can be raised during the OAuth2 flow."""

    def __init__(
        self,
        error: Literal[
            "invalid_request",
            "invalid_client",
            "invalid_scope",
            "unauthorized_client",
            "server_error",
        ],
        description: str,
        status_code: Literal[400, 401, 403, 500],
    ):
        self.error = error
        self.status_code = status_code
        self.description = description
