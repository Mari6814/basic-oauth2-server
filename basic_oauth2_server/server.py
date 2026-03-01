"""FastAPI OAuth server implementation."""

import logging
from typing import Annotated

from fastapi import FastAPI, Form, Request
from fastapi.responses import JSONResponse

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import Database, ClientRepository
from basic_oauth2_server.grants.client_credentials import (
    handle_client_credentials_grant,
)
from basic_oauth2_server.jwks import build_jwks
from basic_oauth2_server.token_service import make_token_factory
from basic_oauth2_server.exceptions import OAuthError

logger = logging.getLogger(__name__)


class OAuthServer:
    """Central OAuth server object.

    Holds the server configuration, database connection, and JWKS document.
    Creates per-request contexts with session-scoped repositories and services.
    """

    def __init__(self, config: ServerConfig):
        self.config = config
        self.db = Database(config.db_path)
        self.db.create_tables()
        self.jwks_document = build_jwks(config)
        logger.info("OAuth server initialized with db: %s", config.db_path)

    def create_app(self) -> FastAPI:
        """Create the FastAPI application."""
        app = FastAPI(title="Basic OAuth Server", version="0.1.0")
        app.state.config = self.config
        server = self
        _create_token = make_token_factory(self.config)

        @app.get("/.well-known/jwks.json")
        async def jwks_endpoint() -> JSONResponse:
            """Serve the JSON Web Key Set for configured asymmetric keys."""
            return JSONResponse(content=server.jwks_document)

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

            with server.db.session() as session:
                client_repo = ClientRepository(session)

                def authenticate_client(client_id: str, secret: bytes):
                    client = client_repo.get(client_id)
                    if client and client.verify_client_secret(secret):
                        return client
                    return None

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
                                    expires_in=server.config.token_expires_in,
                                    authenticate_client=authenticate_client,
                                    create_token=_create_token,
                                    record_usage=client_repo.touch_last_used,
                                )
                            )
                        case _:
                            return _oauth_error(
                                "unsupported_grant_type",
                                f"Unsupported grant type: {grant_type}",
                                status_code=400,
                            )
                except OAuthError as e:
                    return _oauth_error(
                        e.error, e.description, status_code=e.status_code
                    )
                except Exception as e:
                    logger.error("Error processing token request: %s", e)
                    return _oauth_error(
                        "server_error",
                        f"An error occurred while processing the token request: {e}",
                        status_code=500,
                    )

        return app


def create_app(config: ServerConfig) -> FastAPI:
    """Create the FastAPI application with the given configuration."""
    server = OAuthServer(config)
    return server.create_app()


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """Return an OAuth error response."""
    logger.warning("OAuth error: %s (%s) - %s", error, status_code, description)
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


def run_server(config: ServerConfig) -> None:
    """Run the OAuth server with the given configuration."""
    import uvicorn

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)
