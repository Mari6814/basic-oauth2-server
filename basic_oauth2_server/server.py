"""FastAPI OAuth server implementation."""

import logging
import time
from typing import Annotated, Any
from urllib.parse import urlencode

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Form, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from jws_algorithms import SymmetricAlgorithm

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import (
    Client,
    delete_refresh_token,
    get_client,
    get_user,
    init_db,
)
from basic_oauth2_server.exceptions import (
    AuthorizationRedirectException,
    InvalidClientException,
    InvalidGrantException,
    InvalidRequestException,
    OAuth2Exception,
)
from basic_oauth2_server.jwks import build_jwks
from basic_oauth2_server.middleware import (
    RateLimitMiddleware,
    TokenCacheControlMiddleware,
)
from basic_oauth2_server.jwt import (
    decode_jwt_without_verification,
    get_algorithm,
    verify_jwt,
)
from .consent_token import (
    verify_consent_token,
)
from .client_credentials_grant import handle_client_credentials
from .authorization_code_grant import (
    handle_authorization_code,
    handle_authorize,
    handle_authorize_confirm,
    handle_refresh_token,
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

    # Add middlewares in correct order (rate limit before cache control)
    app.add_middleware(TokenCacheControlMiddleware)
    app.add_middleware(RateLimitMiddleware, trust_proxy=config.trust_proxy)
    init_db(config.db_path)
    jwks_document = build_jwks(config)
    well_known_document = {
        "issuer": config.app_url,
        "authorization_endpoint": f"{config.app_url}/authorize",
        "token_endpoint": f"{config.app_url}/oauth2/token",
        "jwks_uri": f"{config.app_url}/.well-known/jwks.json",
        "introspection_endpoint": f"{config.app_url}/oauth2/introspect",
        "revocation_endpoint": f"{config.app_url}/oauth2/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "code_challenge_methods_supported": ["S256"],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
    }
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

    @app.exception_handler(AuthorizationRedirectException)
    async def authorization_redirect_handler(
        request: Request, exc: AuthorizationRedirectException
    ) -> RedirectResponse:
        params = {"error": exc.error, "error_description": exc.description}
        if exc.state:
            params["state"] = exc.state
        return RedirectResponse(
            url=f"{exc.redirect_uri}?{urlencode(params)}",
            status_code=302,
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

    @app.get("/.well-known/oauth-authorization-server")
    async def oauth_authorization_server_metadata_endpoint() -> JSONResponse:
        """Serve OAuth server metadata."""
        return JSONResponse(content=well_known_document)

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
        # TODO (non-standard): This endpoint requires HTTP Basic Auth and returns
        # JSON instead of rendering an HTML login/consent page and redirecting.
        # No standardized OAuth client can drive this. The Idea was that I want to
        # keep it simple and not have a login page with sessions. But maybe its
        # required to make it work with the standard clients I'm developing this for.
        # TODO (non-standard): `state` is declared required here. Have to document that this is on purpose and to simplify things, we always require state. I'm pretty sure that
        # most providers also require it. Might have to read up on how they handle
        # missing state?
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
        jti: str = claims.jti

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
            consent_jti=jti,
        )
        return RedirectResponse(url=redirect_url, status_code=302)

    @app.post("/oauth2/token")
    async def token_endpoint(
        grant_type: Annotated[str | None, Form()] = None,
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
        audience: Annotated[str | None, Form()] = None,
        code: Annotated[str | None, Form()] = None,
        refresh_token: Annotated[str | None, Form()] = None,
        redirect_uri: Annotated[str | None, Form()] = None,
        code_verifier: Annotated[str | None, Form()] = None,
        client_credentials: Annotated[
            HTTPBasicCredentials | None, Depends(token_security)
        ] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint supporting multiple grant types."""
        if not grant_type:
            raise InvalidRequestException("Missing required parameter: grant_type")

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
            case "refresh_token":
                refresh_token_data = handle_refresh_token(
                    config=config,
                    client_id=effective_client_id,
                    client_secret=effective_client_secret,
                    refresh_token=refresh_token,
                )
                return JSONResponse(content=refresh_token_data)
            case _:
                raise InvalidGrantException("Unsupported grant_type")

    @app.post("/oauth2/introspect")
    async def introspect_endpoint(
        token: Annotated[str, Form()],
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        client_credentials: Annotated[
            HTTPBasicCredentials | None, Depends(token_security)
        ] = None,
    ) -> JSONResponse:
        """Inspect the token to return its claims and status."""
        _authenticate_client(
            config=config,
            client_id=client_id,
            client_secret=client_secret,
            client_credentials=client_credentials,
        )
        claims = _get_active_token_claims(config=config, token=token)
        if claims is None:
            return JSONResponse(content={"active": False})
        return JSONResponse(content={"active": True, **claims})

    @app.post("/oauth2/revoke")
    async def revoke_endpoint(
        token: Annotated[str, Form()],
        token_type_hint: Annotated[str | None, Form()] = None,
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        client_credentials: Annotated[
            HTTPBasicCredentials | None, Depends(token_security)
        ] = None,
    ) -> JSONResponse:
        """Revoke a refresh token according to RFC 7009."""
        _authenticate_client(
            config=config,
            client_id=client_id,
            client_secret=client_secret,
            client_credentials=client_credentials,
        )
        if token_type_hint is not None and token_type_hint != "refresh_token":
            raise OAuth2Exception(
                "unsupported_token_type",
                "Only refresh_token revocation is supported",
                400,
            )

        delete_refresh_token(config.db_path, token)
        return JSONResponse(content={})

    return app


def _render_oauth_error(
    error: str, description: str, status_code: int = 400
) -> JSONResponse:
    """Return a JSON response according to what OAuth2 expects."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


def run_server(config: ServerConfig) -> None:  # pragma: no cover
    """Run the OAuth server with the given configuration."""
    import uvicorn

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)


def _authenticate_client(
    config: ServerConfig,
    client_id: str | None,
    client_secret: str | None,
    client_credentials: HTTPBasicCredentials | None,
) -> Client:
    """Authenticate a client using HTTP Basic auth or form credentials."""
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

    client = get_client(config.db_path, effective_client_id)
    if not client or not client.verify_client_secret(effective_client_secret):
        raise InvalidClientException("Client authentication failed")
    return client


def _get_active_token_claims(config: ServerConfig, token: str) -> dict[str, Any] | None:
    """Return verified claims for an active token, or None when inactive."""
    decoded_token = decode_jwt_without_verification(token)
    if decoded_token is None:
        return None

    header, claims = decoded_token
    algorithm_name = header.get("alg")
    token_client_id = claims.get("client_id")
    if not isinstance(algorithm_name, str) or not isinstance(token_client_id, str):
        return None

    client = get_client(config.db_path, token_client_id)
    if not client or client.algorithm != algorithm_name:
        return None

    try:
        algorithm = get_algorithm(client.algorithm)
    except ValueError:
        return None
    if isinstance(algorithm, SymmetricAlgorithm):
        signing_secret = client.get_signing_secret()
        if signing_secret is None:
            return None
        verified_claims = verify_jwt(
            token, algorithm=algorithm, secret=signing_secret, public_key=None
        )
    else:
        try:
            private_key, _ = config.load_private_key(algorithm)
            public_key = _derive_public_key(private_key)
        except Exception:
            return None
        verified_claims = verify_jwt(
            token, algorithm=algorithm, secret=None, public_key=public_key
        )

    if verified_claims is None:
        return None

    return verified_claims


def _derive_public_key(private_key: bytes) -> Any:
    """Derive a public key object from PEM-encoded private key bytes."""
    loaded_private_key = serialization.load_pem_private_key(private_key, password=None)
    return loaded_private_key.public_key()
