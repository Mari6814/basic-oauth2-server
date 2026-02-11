"""FastAPI OAuth server implementation."""

import logging
from typing import Annotated

from fastapi import FastAPI, Form
from fastapi.responses import JSONResponse

from basic_oauth2_server.config import ServerConfig
from basic_oauth2_server.db import Client, get_client, init_db, touch_client_last_used
from basic_oauth2_server.jwt import create_access_token, get_algorithm, is_symmetric
from basic_oauth2_server.secrets import parse_secret

logger = logging.getLogger(__name__)
DEFAULT_EXPIRES_IN = 3600


def create_app(config: ServerConfig) -> FastAPI:
    """Create the FastAPI application with the given configuration."""
    app = FastAPI(title="Basic OAuth Server", version="0.1.0")

    # Store config in app state
    app.state.config = config

    # Initialize database
    init_db(config.db_path)
    logger.info("OAuth server initialized with db: %s", config.db_path)

    @app.post("/oauth/token")
    async def token_endpoint(
        grant_type: Annotated[str, Form()],
        client_id: Annotated[str, Form()],
        client_secret: Annotated[str, Form()],
        scope: Annotated[str | None, Form()] = None,
        audience: Annotated[str | None, Form()] = None,
    ) -> JSONResponse:
        """OAuth 2.0 token endpoint for client_credentials grant."""
        # Validate grant type
        if grant_type != "client_credentials":
            logger.warning("Unsupported grant type: %s", grant_type)
            return _oauth_error(
                "unsupported_grant_type",
                "Only client_credentials grant type is supported",
                status_code=400,
            )

        # Get client from database
        client = get_client(config.db_path, client_id)
        if not client:
            logger.warning("Unknown client_id: %s", client_id)
            return _oauth_error(
                "invalid_client",
                "Client authentication failed",
                status_code=401,
            )

        # Validate client secret
        if not _validate_client_secret(client, client_secret):
            logger.warning("Invalid secret for client: %s", client_id)
            return _oauth_error(
                "invalid_client",
                "Client authentication failed",
                status_code=401,
            )

        # Validate and process scopes
        requested_scopes: list[str] = []
        if scope:
            requested_scopes = scope.split()
            allowed_scopes = client.get_scopes_list()
            if allowed_scopes:
                for s in requested_scopes:
                    if s not in allowed_scopes:
                        return _oauth_error(
                            "invalid_scope",
                            f"Scope '{s}' is not allowed for this client",
                            status_code=400,
                        )
            elif requested_scopes:
                return _oauth_error(
                    "invalid_scope",
                    "This client has no configured scopes",
                    status_code=400,
                )

        # Validate audience
        if audience:
            allowed_audiences = client.get_audiences_list()
            if allowed_audiences:
                if audience not in allowed_audiences:
                    return _oauth_error(
                        "invalid_target",
                        f"Audience '{audience}' is not allowed for this client",
                        status_code=400,
                    )
            else:
                return _oauth_error(
                    "invalid_target",
                    "This client has no configured audiences",
                    status_code=400,
                )

        # Create access token
        try:
            access_token = _create_token_for_client(
                config,
                client,
                scopes=requested_scopes if requested_scopes else None,
                audience=audience,
            )
            # Update last_used_at timestamp
            touch_client_last_used(config.db_path, client_id)
            logger.info(
                "Issued token for client: %s (algorithm: %s)",
                client_id,
                client.algorithm,
            )
        except Exception as e:
            logger.error("Failed to create token for client %s: %s", client_id, e)
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


def _validate_client_secret(client: Client, provided_secret: str) -> bool:
    """Validate the provided client secret against the stored hash."""
    return client.verify_secret(provided_secret)


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
    alg_name = client.algorithm

    if is_symmetric(algorithm):
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
        private_key_str = _get_private_key_for_algorithm(config, alg_name)
        if not private_key_str:
            raise ValueError(
                f"No private key configured for {alg_name}. "
                f"Set the appropriate --*-private-key option or environment variable."
            )
        private_key = parse_secret(private_key_str)
        kid = _get_key_id_for_algorithm(config, alg_name)
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


def _get_private_key_for_algorithm(config: ServerConfig, algorithm: str) -> str | None:
    """Get the appropriate private key for the given algorithm."""
    if algorithm in ("RS256", "RS384", "RS512"):
        return config.rsa_private_key
    elif algorithm == "ES256":
        return config.ec_p256_private_key
    elif algorithm == "ES384":
        return config.ec_p384_private_key
    elif algorithm == "ES512":
        return config.ec_p521_private_key
    elif algorithm in ("EdDSA", "Ed25519"):
        return config.eddsa_private_key
    return None


def _get_key_id_for_algorithm(config: ServerConfig, algorithm: str) -> str | None:
    """Get the key ID for the given algorithm."""
    if algorithm in ("RS256", "RS384", "RS512"):
        return config.rsa_key_id
    elif algorithm == "ES256":
        return config.ec_p256_key_id
    elif algorithm == "ES384":
        return config.ec_p384_key_id
    elif algorithm == "ES512":
        return config.ec_p521_key_id
    elif algorithm in ("EdDSA", "Ed25519"):
        return config.eddsa_key_id
    return None


def _oauth_error(error: str, description: str, status_code: int = 400) -> JSONResponse:
    """Return an OAuth error response."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error, "error_description": description},
    )


def run_server(config: ServerConfig) -> None:
    """Run the OAuth server with the given configuration."""
    import uvicorn

    app = create_app(config)
    uvicorn.run(app, host=config.host, port=config.port)
