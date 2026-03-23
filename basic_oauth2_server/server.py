"""FastAPI OAuth server implementation."""

import logging
from typing import Annotated

from fastapi import FastAPI, Form, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials


from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import init_db
from basic_oauth2_server.exceptions import (
    InvalidClientException,
    InvalidGrantException,
    InvalidRequestException,
    OAuth2Exception,
)
from basic_oauth2_server.jwks import build_jwks
from .client_credentials_grant import handle_client_credentials
from .authorization_code_grant import (
    handle_authorization_code,
    handle_authorize,
    handle_authorize_confirm,
)

logger = logging.getLogger(__name__)
DEFAULT_EXPIRES_IN = 3600

# set up Authorization: Basic base64(client_id:client_secret), but ignore errors
security = HTTPBasic(auto_error=False)
# Basic auth that returns 401 if not provided. Because {error: invalid_client} is not needed for this case
login_security = HTTPBasic(auto_error=True, realm="OAuth Authorization")


def create_app(config: ServerConfig) -> FastAPI:
    """Create the FastAPI application with the given configuration."""
    app = FastAPI(title="Basic OAuth Server", version="0.1.0")
    app.state.config = config
    init_db(config.db_path)
    jwks_document = build_jwks(config)
    logger.info("OAuth server initialized with db: %s", config.db_path)

    @app.exception_handler(OAuth2Exception)
    async def oauth_exception_handler(
        request: Request, exc: OAuth2Exception
    ) -> JSONResponse:
        if exc.status_code not in [401, 403]:
            logger.warning(
                "OAuth error: %s (%s) - %s",
                exc.error,
                exc.status_code,
                exc.description,
            )
        return _render_oauth_error(
            exc.error, exc.description or "", status_code=exc.status_code
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.error("Unexpected error: %s", exc)
        return _render_oauth_error(
            "server_error", "An unexpected error occurred", status_code=500
        )

    @app.get("/.well-known/jwks.json")
    async def jwks_endpoint() -> JSONResponse:
        """Serve the JSON Web Key Set for configured asymmetric keys."""
        return JSONResponse(content=jwks_document)

    @app.get("/authorize")
    async def authorize_endpoint(
        response_type: Annotated[str, Query()],
        client_id: Annotated[str, Query()],
        redirect_uri: Annotated[str, Query()],
        code_challenge: Annotated[str, Query()],
        user: Annotated[HTTPBasicCredentials, Depends(login_security)],
        code_challenge_method: Annotated[str, Query()] = "S256",
        scope: Annotated[str | None, Query()] = None,
        audience: Annotated[str | None, Query()] = None,
        state: Annotated[str | None, Query()] = None,
    ) -> JSONResponse:
        """Authorization endpoint. Requires HTTP Basic Auth to identify the user.

        Returns a JSON consent page with a confirm link.
        """
        # TODO: Use the `user`-object to authenticate the user (separate from client)
        if response_type != "code":
            raise InvalidRequestException("Unsupported response_type")
        consent_data = handle_authorize(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope.split() if scope else None,
            audience=audience,
            state=state,
            username=user.username,
            config=config,
        )
        return JSONResponse(content=consent_data)

    @app.get("/authorize/confirm")
    async def authorize_confirm(
        client_id: Annotated[str, Query()],
        redirect_uri: Annotated[str, Query()],
        code_challenge: Annotated[str, Query()],
        user: Annotated[HTTPBasicCredentials, Depends(login_security)],
        code_challenge_method: Annotated[str, Query()] = "S256",
        scope: Annotated[str | None, Query()] = None,
        audience: Annotated[str | None, Query()] = None,
        state: Annotated[str | None, Query()] = None,
    ) -> RedirectResponse:
        """Consent confirmation endpoint. Generates an auth code and redirects."""
        # TODO: Either use the `user`-objec to authenticate or require that this endpoint is handled via session cookies after the initial auth.
        redirect_url = handle_authorize_confirm(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope.split() if scope else None,
            audience=audience,
            state=state,
            user_username=user.username,
            user_password=user.password,
            config=config,
        )
        return RedirectResponse(url=redirect_url, status_code=302)

    @app.post("/oauth2/token")
    async def token_endpoint(
        grant_type: Annotated[str, Form()],
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
        audience: Annotated[str | None, Form()] = None,
        code: Annotated[str | None, Form()] = None,
        redirect_uri: Annotated[str | None, Form()] = None,
        code_verifier: Annotated[str | None, Form()] = None,
        client_credentials: Annotated[
            HTTPBasicCredentials | None, Depends(security)
        ] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint supporting multiple grant types."""
        match grant_type:
            case "client_credentials":
                effective_client_id = (
                    client_credentials.username if client_credentials else client_id
                )
                effective_client_secret = (
                    client_credentials.password if client_credentials else client_secret
                )
                if not effective_client_id or not effective_client_secret:
                    raise InvalidClientException(
                        "Client authentication failed: missing credentials"
                    )
                client_credentials_data = handle_client_credentials(
                    config=config,
                    client_id=effective_client_id,
                    client_secret=effective_client_secret,
                    scope=scope,
                    audience=audience,
                )
                return JSONResponse(content=client_credentials_data)
            case "authorization_code":
                return handle_authorization_code(
                    config,
                    client_id,
                    code,
                    redirect_uri,
                    code_verifier,
                )
            case _:
                raise InvalidGrantException("Unsupported grant_type")

    return app


def _render_oauth_error(
    error: str, description: str, status_code: int = 400
) -> JSONResponse:
    """Return a JSON response according to what OAuth2 excepts."""
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
