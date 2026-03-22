"""FastAPI OAuth server implementation."""

import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Annotated
from urllib.parse import urlencode

from fastapi import FastAPI, Form, Depends, Query
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials


from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import (
    create_authorization_code,
    get_authorization_code,
    get_client,
    init_db,
    mark_authorization_code_used,
    touch_client_last_used,
)
from basic_oauth2_server.exceptions import OAuth2Exception
from basic_oauth2_server.jwks import build_jwks
from basic_oauth2_server.token_service import create_access_token_for_client
from .client_credentials_grant import handle_client_credentials

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
        if response_type != "code":
            return _oauth_error(
                "unsupported_response_type",
                "Only response_type=code is supported",
                status_code=400,
            )

        if code_challenge_method not in ("S256", "plain"):
            return _oauth_error(
                "invalid_request",
                "code_challenge_method must be S256 or plain",
                status_code=400,
            )

        client = get_client(config.db_path, client_id)
        if not client:
            return _oauth_error(
                "invalid_client",
                f"Unknown client_id: {client_id}",
                status_code=400,
            )

        requested_scopes = scope.split() if scope else []
        if requested_scopes:
            allowed_scopes = client.get_scopes_list()
            invalid = [s for s in requested_scopes if s not in allowed_scopes]
            if invalid:
                return _oauth_error(
                    "invalid_scope",
                    f"Invalid scopes: {', '.join(invalid)}",
                    status_code=400,
                )

        if audience:
            allowed_audiences = client.get_audiences_list()
            if audience not in allowed_audiences:
                return _oauth_error(
                    "invalid_audience",
                    f"Invalid audience: {audience}",
                    status_code=400,
                )

        # Build confirm link
        confirm_params: dict[str, str] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        if scope:
            confirm_params["scope"] = scope
        if audience:
            confirm_params["audience"] = audience
        if state:
            confirm_params["state"] = state

        base_url = config.app_url or ""
        confirm_url = f"{base_url}/authorize/confirm?{urlencode(confirm_params)}"

        consent_data = {
            "type": "consent",
            "message": f"Application '{client_id}' is requesting access.",
            "user": user.username,
            "client_id": client_id,
            "requested_scopes": requested_scopes or [],
            "audience": audience,
            "redirect_uri": redirect_uri,
            "confirm_url": confirm_url,
        }

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
        code = create_authorization_code(
            db_path=config.db_path,
            client_id=client_id,
            user_id=user.username,
            redirect_uri=redirect_uri,
            scope=scope,
            audience=audience,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        redirect_params: dict[str, str] = {"code": code}
        if state:
            redirect_params["state"] = state

        redirect_url = f"{redirect_uri}?{urlencode(redirect_params)}"
        logger.info(
            "Authorization code issued for client %s, user %s",
            client_id,
            user.username,
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
        basic_credentials: Annotated[
            HTTPBasicCredentials | None, Depends(security)
        ] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint supporting multiple grant types."""
        try:
            match grant_type:
                case "client_credentials":
                    return handle_client_credentials(
                        config,
                        client_id,
                        client_secret,
                        scope,
                        audience,
                        basic_credentials,
                    )
                case "authorization_code":
                    return handle_authorization_code(
                        config,
                        client_id,
                        code,
                        redirect_uri,
                        code_verifier,
                    )
                case _:
                    return _oauth_error(
                        "invalid_grant",
                        f"Grant type '{grant_type}' is not supported",
                        status_code=400,
                    )
        except OAuth2Exception as exc:
            return _oauth_error(
                exc.error,
                exc.description or "",
                status_code=exc.status_code,
            )

    return app


def _verify_pkce(
    code_verifier: str, code_challenge: str, code_challenge_method: str
) -> bool:
    """Verify a PKCE code_verifier against the stored code_challenge."""
    if code_challenge_method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return computed == code_challenge
    elif code_challenge_method == "plain":
        return code_verifier == code_challenge
    return False


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """Return an OAuth error response."""
    logger.warning("OAuth error: %s (%s) - %s", error, status_code, description)
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


def handle_authorization_code(
    config: ServerConfig,
    client_id: str | None,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> JSONResponse:
    """Handle the authorization_code grant type with PKCE validation."""
    if not code:
        return _oauth_error(
            "invalid_request", "Missing authorization code", status_code=400
        )
    if not client_id:
        return _oauth_error("invalid_request", "Missing client_id", status_code=400)
    if not code_verifier:
        return _oauth_error(
            "invalid_request", "Missing code_verifier (PKCE required)", status_code=400
        )

    auth_code = get_authorization_code(config.db_path, code)
    if not auth_code:
        return _oauth_error(
            "invalid_grant", "Invalid authorization code", status_code=400
        )

    if auth_code.used:
        return _oauth_error(
            "invalid_grant", "Authorization code already used", status_code=400
        )

    if auth_code.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return _oauth_error(
            "invalid_grant", "Authorization code expired", status_code=400
        )

    if auth_code.client_id != client_id:
        return _oauth_error("invalid_grant", "Client ID mismatch", status_code=400)

    if auth_code.redirect_uri and auth_code.redirect_uri != redirect_uri:
        return _oauth_error("invalid_grant", "Redirect URI mismatch", status_code=400)

    if auth_code.code_challenge:
        if not _verify_pkce(
            code_verifier, auth_code.code_challenge, auth_code.code_challenge_method
        ):
            return _oauth_error(
                "invalid_grant", "PKCE code_verifier validation failed", status_code=400
            )

    mark_authorization_code_used(config.db_path, code)

    client = get_client(config.db_path, client_id)
    if not client:
        return _oauth_error("invalid_client", "Client not found", status_code=401)

    scopes = auth_code.scope.split() if auth_code.scope else None

    try:
        access_token = create_access_token_for_client(
            config,
            client,
            scopes=scopes,
            audience=auth_code.audience,
            subject=auth_code.user_id,
        )
        touch_client_last_used(config.db_path, client_id)
        logger.info(
            "Issued token via authorization_code for client: %s, user: %s",
            client_id,
            auth_code.user_id,
        )
    except Exception as e:
        logger.error("Failed to create token for client %s: %s", client_id, e)
        return _oauth_error(
            "server_error", f"Failed to create token: {e}", status_code=500
        )

    response_data: dict[str, str | int] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": DEFAULT_EXPIRES_IN,
    }
    if scopes:
        response_data["scope"] = " ".join(scopes)

    return JSONResponse(content=response_data)


def run_server(config: ServerConfig) -> None:
    """Run the OAuth server with the given configuration."""
    import uvicorn

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)
