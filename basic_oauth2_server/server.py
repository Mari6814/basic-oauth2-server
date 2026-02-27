"""FastAPI OAuth server implementation."""

import base64
import logging
from typing import Annotated

from fastapi import FastAPI, Form, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm


from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import Client, get_client, init_db, touch_client_last_used
from basic_oauth2_server.jwks import build_jwks
from basic_oauth2_server.jwt import create_access_token, get_algorithm
from basic_oauth2_server.secrets import parse_secret

logger = logging.getLogger(__name__)
DEFAULT_EXPIRES_IN = 3600

# set up Authorization: Basic base64(client_id:client_secret), but ignore errors
security = HTTPBasic(auto_error=False)


def create_app(config: ServerConfig) -> FastAPI:
    """Create the FastAPI application with the given configuration."""
    app = FastAPI(title="Basic OAuth Server", version="0.1.0")

    # Store config in app state
    app.state.config = config

    # Initialize database
    init_db(config.db_path)
    logger.info("OAuth server initialized with db: %s", config.db_path)

    # Build JWKS once at startup (keys don't change at runtime)
    jwks_document = build_jwks(config)

    @app.get("/.well-known/jwks.json")
    async def jwks_endpoint() -> JSONResponse:
        """Serve the JSON Web Key Set for configured asymmetric keys."""
        return JSONResponse(content=jwks_document)

    @app.post("/oauth2/token")
    async def token_endpoint(
        grant_type: Annotated[str, Form()],
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
        scope: Annotated[str | None, Form()] = None,
        audience: Annotated[str | None, Form()] = None,
        basic_credentials: Annotated[
            HTTPBasicCredentials | None, Depends(security)
        ] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint for client_credentials grant.

        Supports client authentication via:
        - HTTP Basic Authorization header (preferred)
        - Form-encoded client_id and client_secret
        """
        if basic_credentials:
            effective_client_id = basic_credentials.username
            effective_client_secret = basic_credentials.password
        elif client_id and client_secret:
            effective_client_id, effective_client_secret = client_id, client_secret
        else:
            return _oauth_error(
                "invalid_client",
                "Client authentication failed: missing credentials",
                status_code=401,
            )
        try:
            effective_client_secret_bytes = base64.b64decode(
                effective_client_secret, validate=True
            )
        except Exception:
            return _oauth_error(
                "invalid_client",
                "Client authentication failed: invalid base64 encoding in secret",
                status_code=401,
            )

        if grant_type != "client_credentials":
            return _oauth_error(
                "unsupported_grant_type",
                "Only client_credentials grant type is supported",
                status_code=400,
            )

        client = get_client(config.db_path, effective_client_id)
        if not client:
            return _oauth_error(
                "invalid_client",
                "Client authentication failed",
                status_code=401,
            )

        if not client.verify_client_secret(effective_client_secret_bytes):
            return _oauth_error(
                "invalid_client",
                "Client authentication failed",
                status_code=401,
            )

        requested_scopes: list[str] = []
        if scope:
            requested_scopes = scope.split()
            allowed_scopes = client.get_scopes_list()
            invalid_scopes = [
                scope for scope in requested_scopes if scope not in allowed_scopes
            ]
            if invalid_scopes:
                logger.warning(
                    "Client %s requested invalid scopes: %s",
                    effective_client_id,
                    ", ".join(invalid_scopes),
                )
                return _oauth_error(
                    "invalid_scope",
                    "Requested scopes not allowed for this client",
                    status_code=400,
                )

        if audience:
            allowed_audiences = client.get_audiences_list()
            if audience not in allowed_audiences:
                return _oauth_error(
                    "invalid_audience",
                    f"Requested audience not allowed for this client: {audience}",
                    status_code=400,
                )

        try:
            access_token = _create_token_for_client(
                config,
                client,
                scopes=requested_scopes if requested_scopes else None,
                audience=audience,
            )
            touch_client_last_used(config.db_path, effective_client_id)
            logger.info(
                "Issued token for client: %s (algorithm: %s)",
                effective_client_id,
                client.algorithm,
            )
        except Exception as e:
            logger.error(
                "Failed to create token for client %s: %s", effective_client_id, e
            )
            return _oauth_error(
                "server_error",
                f"Failed to create token: {e}",
                status_code=500,
            )

        response_data = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": DEFAULT_EXPIRES_IN,
        }
        if requested_scopes:
            response_data["scope"] = " ".join(requested_scopes)

        return JSONResponse(content=response_data)

    return app


def _create_token_for_client(
    config: ServerConfig,
    client: Client,
    scopes: list[str] | None = None,
    audience: str | None = None,
) -> str:
    """Create an access token for the given client.

    For symmetric algorithms (HS*), uses the client's signing secret.
    For asymmetric algorithms (RS*, ES*, EdDSA), uses the server's private key
    matching the algorithm family.
    """
    algorithm = get_algorithm(client.algorithm)

    # is_symmetric sucks because type checker doesn't understand it...
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
            expires_in=DEFAULT_EXPIRES_IN,
            issuer=config.app_url,
        )
    else:
        # Select the correct private key based on algorithm
        private_key_str, kid = _get_private_key_for_algorithm(config, algorithm)
        if not private_key_str:
            raise ValueError(
                f"No private key configured for {algorithm}. "
                f"Set the appropriate --*-private-key option or environment variable."
            )
        # TODO: Use functools cache to load key from file
        private_key = parse_secret(private_key_str)
        return create_access_token(
            client_id=client.client_id,
            algorithm=algorithm,
            private_key=private_key,
            scopes=scopes,
            audience=audience,
            expires_in=DEFAULT_EXPIRES_IN,
            kid=kid,
            issuer=config.app_url,
        )


def _get_private_key_for_algorithm(
    config: ServerConfig, algorithm: AsymmetricAlgorithm
) -> tuple[str | None, str | None]:
    """Get the appropriate private key for the given algorithm."""
    match algorithm:
        case (
            AsymmetricAlgorithm.RS256
            | AsymmetricAlgorithm.RS384
            | AsymmetricAlgorithm.RS512
            | AsymmetricAlgorithm.PS256
            | AsymmetricAlgorithm.PS384
            | AsymmetricAlgorithm.PS512
        ):
            return config.rsa_private_key, config.rsa_key_id
        case AsymmetricAlgorithm.ES256:
            return config.ec_p256_private_key, config.ec_p256_key_id
        case AsymmetricAlgorithm.ES384:
            return config.ec_p384_private_key, config.ec_p384_key_id
        case AsymmetricAlgorithm.ES512:
            return config.ec_p521_private_key, config.ec_p521_key_id
        case AsymmetricAlgorithm.EdDSA:
            return config.eddsa_private_key, config.eddsa_key_id
        case _:
            return None, None


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
