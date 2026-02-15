"""Command-line interface for basic-oauth2-server."""

from __future__ import annotations

import argparse
import base64
import logging
import os
import secrets
import sys

from basic_oauth2_server.db import create_client, get_client, init_db
from basic_oauth2_server.jwt import get_algorithm, is_symmetric
from basic_oauth2_server.secrets import parse_secret
from basic_oauth2_server.db import list_clients
from basic_oauth2_server.db import delete_client

logger = logging.getLogger(__name__)


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="basic-oauth2-server",
        description="Basic OAuth 2.0 Authorization Server",
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # serve command
    serve_parser = subparsers.add_parser("serve", help="Start the OAuth server")
    serve_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("OAUTH_PORT", "8080")),
        help="Port to listen on (default: 8080)",
    )
    serve_parser.add_argument(
        "--host",
        default=os.environ.get("OAUTH_HOST", "localhost"),
        help="Host to bind to (default: localhost)",
    )
    serve_parser.add_argument(
        "--db",
        default=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        help="Path to SQLite database (default: ./oauth.db)",
    )
    serve_parser.add_argument(
        "--rsa-private-key",
        default=os.environ.get("OAUTH_RSA_PRIVATE_KEY"),
        help="RSA private key for RS256/RS384/RS512 (@file or PEM format)",
    )
    serve_parser.add_argument(
        "--ec-p256-private-key",
        default=os.environ.get("OAUTH_EC_P256_PRIVATE_KEY"),
        help="ECDSA P-256 private key for ES256 (@file or PEM format)",
    )
    serve_parser.add_argument(
        "--ec-p384-private-key",
        default=os.environ.get("OAUTH_EC_P384_PRIVATE_KEY"),
        help="ECDSA P-384 private key for ES384 (@file or PEM format)",
    )
    serve_parser.add_argument(
        "--ec-p521-private-key",
        default=os.environ.get("OAUTH_EC_P521_PRIVATE_KEY"),
        help="ECDSA P-521 private key for ES512 (@file or PEM format)",
    )
    serve_parser.add_argument(
        "--eddsa-private-key",
        default=os.environ.get("OAUTH_EDDSA_PRIVATE_KEY"),
        help="Ed25519 private key for EdDSA (@file or PEM format)",
    )
    serve_parser.add_argument(
        "--rsa-key-id",
        default=os.environ.get("OAUTH_RSA_KEY_ID"),
        help="Key ID for RSA keys (included in JWT header as 'kid')",
    )
    serve_parser.add_argument(
        "--ec-p256-key-id",
        default=os.environ.get("OAUTH_EC_P256_KEY_ID"),
        help="Key ID for EC P-256 key (included in JWT header as 'kid')",
    )
    serve_parser.add_argument(
        "--ec-p384-key-id",
        default=os.environ.get("OAUTH_EC_P384_KEY_ID"),
        help="Key ID for EC P-384 key (included in JWT header as 'kid')",
    )
    serve_parser.add_argument(
        "--ec-p521-key-id",
        default=os.environ.get("OAUTH_EC_P521_KEY_ID"),
        help="Key ID for EC P-521 key (included in JWT header as 'kid')",
    )
    serve_parser.add_argument(
        "--eddsa-key-id",
        default=os.environ.get("OAUTH_EDDSA_KEY_ID"),
        help="Key ID for EdDSA key (included in JWT header as 'kid')",
    )
    serve_parser.add_argument(
        "--app-url",
        default=os.environ.get("APP_URL"),
        help="Issuer URL for JWT 'iss' claim (e.g., https://auth.example.com)",
    )

    # clients command
    clients_parser = subparsers.add_parser("clients", help="Manage OAuth clients")
    clients_subparsers = clients_parser.add_subparsers(
        dest="clients_command", help="Client commands"
    )

    # clients create
    create_parser = clients_subparsers.add_parser("create", help="Create a new client")
    create_parser.add_argument("--client-id", required=True, help="Client identifier")
    create_parser.add_argument(
        "--client-secret",
        help="Client secret (password for obtaining tokens). Supports @file, base64:, 0x formats",
    )
    create_parser.add_argument(
        "--algorithm",
        default="HS256",
        choices=[alg.name for alg in SymmetricAlgorithm]
        + [alg.name for alg in AsymmetricAlgorithm],
        help="JWT signing algorithm the client wants (default: HS256)",
    )
    create_parser.add_argument(
        "--signing-secret",
        help="Signing secret for HMAC algorithms (required for HS*). Supports @file, base64:, 0x formats",
    )
    create_parser.add_argument(
        "--scopes",
        help="Comma-separated list of allowed scopes",
    )
    create_parser.add_argument(
        "--audiences",
        help="Comma-separated list of allowed audiences",
    )
    create_parser.add_argument(
        "--db",
        default=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        help="Path to SQLite database",
    )

    # clients list
    list_parser = clients_subparsers.add_parser("list", help="List all clients")
    list_parser.add_argument(
        "--db",
        default=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        help="Path to SQLite database",
    )

    # clients delete
    delete_parser = clients_subparsers.add_parser("delete", help="Delete a client")
    delete_parser.add_argument("--client-id", required=True, help="Client identifier")
    delete_parser.add_argument(
        "--db",
        default=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        help="Path to SQLite database",
    )

    # admin command
    admin_parser = subparsers.add_parser("admin", help="Start the admin dashboard")
    admin_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("OAUTH_ADMIN_PORT", "8081")),
        help="Port to listen on (default: 8081)",
    )
    admin_parser.add_argument(
        "--host",
        default=os.environ.get("OAUTH_ADMIN_HOST", "localhost"),
        help="Host to bind to (default: localhost)",
    )
    admin_parser.add_argument(
        "--db",
        default=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        help="Path to SQLite database",
    )

    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 1

    if parsed.command == "serve":
        return _cmd_serve(parsed)
    elif parsed.command == "clients":
        return _cmd_clients(parsed)
    elif parsed.command == "admin":
        return _cmd_admin(parsed)

    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Handle the 'serve' command."""
    from basic_oauth2_server.config import ServerConfig
    from basic_oauth2_server.server import run_server

    config = ServerConfig(
        host=args.host,
        port=args.port,
        db_path=args.db,
        app_url=args.app_url,
        rsa_private_key=args.rsa_private_key,
        ec_p256_private_key=args.ec_p256_private_key,
        ec_p384_private_key=args.ec_p384_private_key,
        ec_p521_private_key=args.ec_p521_private_key,
        eddsa_private_key=args.eddsa_private_key,
        rsa_key_id=args.rsa_key_id,
        ec_p256_key_id=args.ec_p256_key_id,
        ec_p384_key_id=args.ec_p384_key_id,
        ec_p521_key_id=args.ec_p521_key_id,
        eddsa_key_id=args.eddsa_key_id,
    )

    print(f"Starting OAuth server on {config.host}:{config.port}")
    run_server(config)
    return 0


def _cmd_clients(args: argparse.Namespace) -> int:
    """Handle the 'clients' command."""
    if not args.clients_command:
        print("Usage: basic-oauth2-server clients {create,list,delete}")
        return 1

    if args.clients_command == "create":
        return _cmd_clients_create(args)
    elif args.clients_command == "list":
        return _cmd_clients_list(args)
    elif args.clients_command == "delete":
        return _cmd_clients_delete(args)

    return 0


def _cmd_clients_create(args: argparse.Namespace) -> int:
    """Handle 'clients create' command."""
    init_db(args.db)

    # Check if client already exists
    existing = get_client(args.db, args.client_id)
    if existing:
        print(f"Error: Client '{args.client_id}' already exists", file=sys.stderr)
        return 1

    algorithm = args.algorithm
    signing_secret: bytes | None = None
    generated_signing_secret: str | None = None

    # For symmetric algorithms, auto-generate signing secret if not provided
    if is_symmetric(get_algorithm(algorithm)):
        if args.signing_secret:
            signing_secret = parse_secret(args.signing_secret)
        else:
            # Auto-generate a 32-byte signing secret
            signing_secret = secrets.token_bytes(32)
            generated_signing_secret = base64.b64encode(signing_secret).decode()
            logger.info("Auto-generated signing secret for client: %s", args.client_id)

    secret: bytes | None = None
    if args.client_secret:
        secret = parse_secret(args.client_secret)

    scopes = args.scopes.split(",") if args.scopes else None
    audiences = args.audiences.split(",") if args.audiences else None

    create_client(
        db_path=args.db,
        client_id=args.client_id,
        secret=secret,
        algorithm=algorithm,
        signing_secret=signing_secret,
        scopes=scopes,
        audiences=audiences,
    )

    print(f"Created client '{args.client_id}' with algorithm {algorithm}")
    if generated_signing_secret:
        print(f"Generated signing secret: {generated_signing_secret}")
    return 0


def _cmd_clients_list(args: argparse.Namespace) -> int:
    """Handle 'clients list' command."""
    init_db(args.db)
    clients = list_clients(args.db)

    if not clients:
        print("No clients found.")
        return 0

    print(
        f"{'Client ID':<20} {'Algorithm':<10} {'Secret Hash':<16} "
        f"{'Signing FP':<18} {'Scopes':<15} {'Last Used'}"
    )
    print("-" * 110)
    for client in clients:
        scopes = client.scopes or ""
        secret_hash = client.get_secret_hash_truncated() or "(none)"
        signing_fp = client.get_signing_secret_fingerprint() or "(none)"
        last_used = (
            client.last_used_at.strftime("%Y-%m-%d %H:%M")
            if client.last_used_at
            else "(never)"
        )
        print(
            f"{client.client_id:<20} {client.algorithm:<10} {secret_hash:<16} "
            f"{signing_fp:<18} {scopes:<15} {last_used}"
        )

    return 0


def _cmd_clients_delete(args: argparse.Namespace) -> int:
    """Handle 'clients delete' command."""
    if delete_client(args.db, args.client_id):
        print(f"Deleted client '{args.client_id}'")
        return 0
    else:
        print(f"Error: Client '{args.client_id}' not found", file=sys.stderr)
        return 1


def _cmd_admin(args: argparse.Namespace) -> int:
    """Handle the 'admin' command."""
    try:
        from basic_oauth2_server.admin import run_admin
    except ImportError:
        print(
            "Error: The admin dashboard requires gradio, which is not installed.\n"
            "Install it with: pip install basic-oauth2-server[admin]",
            file=sys.stderr,
        )
        return 1

    from basic_oauth2_server.config import AdminConfig

    config = AdminConfig(
        host=args.host,
        port=args.port,
        db_path=args.db,
    )

    print(f"Starting admin dashboard on {config.host}:{config.port}")
    run_admin(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
