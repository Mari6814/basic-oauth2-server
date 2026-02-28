"""FastAPI OAuth server implementation."""

import logging
from functools import cache
from typing import Annotated

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.access_token import create_access_token
from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import Client, get_client, init_db, touch_client_last_used
from basic_oauth2_server.grants.client_credentials import (
    handle_client_credentials_grant,
)
from basic_oauth2_server.jwks import build_jwks
from basic_oauth2_server.jwt import get_algorithm
from basic_oauth2_server.secrets import parse_secret
from basic_oauth2_server.exceptions import OAuthError

logger = logging.getLogger(__name__)


def create_app(config: ServerConfig) -> FastAPI:
    """Create the FastAPI application with the given configuration."""
    app = FastAPI(title="Basic OAuth Server", version="0.1.0")

    app.state.config = config

    init_db(config.db_path)
    logger.info("OAuth server initialized with db: %s", config.db_path)

    jwks_document = build_jwks(config)

    def authenticate_client(client_id: str, secret: bytes) -> Client | None:
        """Look up a client and verify its secret."""
        client = get_client(config.db_path, client_id)
        if client and client.verify_client_secret(secret):
            return client
        return None

    def create_token(
        client: Client, scopes: list[str] | None, audience: str | None
    ) -> str:
        """Create a signed access token for the given client."""
        algorithm = get_algorithm(client.algorithm)

        if isinstance(algorithm, SymmetricAlgorithm):
            signing_secret = client.get_signing_secret()
            if not signing_secret:
                raise ValueError(
                    f"Client '{client.client_id}' has no signing secret configured"
                )
            return create_access_token(
                client_id=client.client_id,
                algorithm=algorithm,
                secret=signing_secret,
                scopes=scopes,
                audience=audience,
                expires_in=config.token_expires_in,
                issuer=config.app_url,
            )

        private_key_str, kid = config.get_private_key_for_algorithm(algorithm)
        if not private_key_str:
            raise ValueError(
                f"No private key configured for {algorithm}. "
                f"Set the appropriate --*-private-key option or environment variable."
            )
        private_key = _load_private_key(private_key_str)
        return create_access_token(
            client_id=client.client_id,
            algorithm=algorithm,
            private_key=private_key,
            scopes=scopes,
            audience=audience,
            expires_in=config.token_expires_in,
            kid=kid,
            issuer=config.app_url,
        )

    def record_usage(client_id: str) -> None:
        """Update the last_used_at timestamp for a client."""
        touch_client_last_used(config.db_path, client_id)

    @app.get("/.well-known/jwks.json")
    async def jwks_endpoint() -> JSONResponse:
        """Serve the JSON Web Key Set for configured asymmetric keys."""
        return JSONResponse(content=jwks_document)

    @app.post("/oauth2/token")
    async def token_endpoint(
        request: Request,
        grant_type: Annotated[str, Form()],
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
        audience: Annotated[str | None, Form()] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint.

        Dispatches to the appropriate grant handler based on grant_type.
        """
        authorization = request.headers.get("authorization")

        try:
            match grant_type:
                case "client_credentials":
                    return JSONResponse(
                        content=handle_client_credentials_grant(
                            authorization_header=authorization,
                            client_id=client_id,
                            client_secret=client_secret,
                            scope=scope,
                            audience=audience,
                            expires_in=config.token_expires_in,
                            authenticate_client=authenticate_client,
                            create_token=create_token,
                            record_usage=record_usage,
                        )
                    )
                case _:
                    return _oauth_error(
                        "unsupported_grant_type",
                        f"Unsupported grant type: {grant_type}",
                        status_code=400,
                    )
        except OAuthError as e:
            return _oauth_error(e.error, e.description, status_code=e.status_code)
        except Exception as e:
            logger.error("Error processing token request: %s", e)
            return _oauth_error(
                "server_error",
                f"An error occurred while processing the token request: {e}",
                status_code=500,
            )

    return app


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """Return an OAuth error response."""
    logger.warning("OAuth error: %s (%s) - %s", error, status_code, description)
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


@cache
def _load_private_key(private_key_str: str) -> bytes:
    """Load and cache a private key from a file path or raw string."""
    return parse_secret(private_key_str)


def run_server(config: ServerConfig) -> None:
    """Run the OAuth server with the given configuration."""
    import uvicorn

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)
