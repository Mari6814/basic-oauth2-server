"""FastAPI OAuth server implementation."""

import logging
from typing import Annotated

from fastapi import FastAPI, Form, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials


from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import get_user, init_db
from basic_oauth2_server.exceptions import (
    InvalidClientException,
    InvalidGrantException,
    InvalidRequestException,
    OAuth2Exception,
)
from basic_oauth2_server.jwks import build_jwks
from .consent_token import (
    create_consent_token,
    verify_consent_token,
)
from .client_credentials_grant import handle_client_credentials
from .authorization_code_grant import (
    handle_authorization_code,
    handle_authorize,
    handle_authorize_confirm,
)

logger = logging.getLogger(__name__)

# auto_error=False so that we can handle the OAuth2 error responses ourselves.
token_security = HTTPBasic(auto_error=False)

# For /authorize, where the web frontend does not care about OAuth2 responses, so we do let it auto_error
authorize_security = HTTPBasic(auto_error=True, realm="OAuth Authorization")


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
        state: Annotated[str, Query()],
        user: Annotated[HTTPBasicCredentials, Depends(authorize_security)],
        code_challenge_method: Annotated[str, Query()] = "S256",
        scope: Annotated[str | None, Query()] = None,
        audience: Annotated[str | None, Query()] = None,
    ) -> JSONResponse:
        """Authorization endpoint. Requires HTTP Basic Auth.

        Validates the user credentials and the authorization request parameters,
        then returns a consent page JSON. The consent page contains a confirm_url
        with a signed JWT that encodes all authorization parameters. The user
        POSTs only that token to /authorize/confirm to complete the flow.
        """
        if response_type != "code":
            raise InvalidRequestException("Unsupported response_type")

        db_user = get_user(config.db_path, user.username)
        if not db_user or not db_user.verify_password(user.password):
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": 'Basic realm="OAuth Authorization"'},
            )

        consent_data = handle_authorize(
            authorized_username=user.username,
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope.split() if scope else None,
            audience=audience,
            state=state,
            config=config,
        )

        base_url = config.app_url or ""
        return JSONResponse(
            content={
                **consent_data,
                "confirm_url": f"{base_url}/authorize/confirm",
            }
        )

    @app.post("/authorize/confirm")
    async def authorize_confirm(
        token: Annotated[str, Form()],
        user: Annotated[HTTPBasicCredentials, Depends(authorize_security)],
    ) -> RedirectResponse:
        """Endpoint that marks the received JWT as consented to by the end user.

        Receives a form POST containing only the signed consent JWT issued by
        GET /authorize. The token is verified and its claims are used to create
        the authorization code. Redirects to the redirect_uri with the code.
        """
        claims = verify_consent_token(token, config=config)

        username: str = claims.username
        client_id: str = claims.client_id
        redirect_uri: str = claims.redirect_uri
        code_challenge: str = claims.code_challenge
        code_challenge_method: str = claims.code_challenge_method
        state: str = claims.state
        scope_str: str | None = claims.scope
        audience: str | None = claims.audience

        db_user = get_user(config.db_path, user.username)
        if not db_user or not db_user.verify_password(user.password):
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": 'Basic realm="OAuth Authorization"'},
            )

        if user.username != username:
            raise HTTPException(
                status_code=403,
                detail="Forbidden: token user does not match authenticated user",
            )

        redirect_url = handle_authorize_confirm(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope_str.split() if scope_str else None,
            audience=audience,
            state=state,
            username=username,
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
            HTTPBasicCredentials | None, Depends(token_security)
        ] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint supporting multiple grant types."""
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
        match grant_type:
            case "client_credentials":
                client_credentials_data = handle_client_credentials(
                    config=config,
                    client_id=effective_client_id,
                    client_secret=effective_client_secret,
                    scope=scope,
                    audience=audience,
                )
                return JSONResponse(content=client_credentials_data)
            case "authorization_code":
                authorization_code_data = handle_authorization_code(
                    config=config,
                    client_id=effective_client_id,
                    client_secret=effective_client_secret,
                    code=code,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                )
                return JSONResponse(content=authorization_code_data)
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
