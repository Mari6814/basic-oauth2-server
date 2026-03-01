"""Command-line interface for basic-oauth2-server."""

from __future__ import annotations

import argparse
import base64
import os
import secrets
import sys
import uuid

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm

from basic_oauth2_server.db import create_client
from basic_oauth2_server.db import list_clients
from basic_oauth2_server.db import delete_client
from basic_oauth2_server.jwt import get_algorithm, is_symmetric
from basic_oauth2_server.utils import decode_prefixed_utf8
from basic_oauth2_server.config import AdminConfig, ServerConfig


def main(args: list[str] | None = None) -> int:
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="basic-oauth2-server",
        description="Basic OAuth 2.0 Authorization Server",
    )
    parser.add_argument(
        "--db",
        default=os.environ.get("OAUTH_DB_PATH", "./oauth.db"),
        help="Path to SQLite database (default: ./oauth.db)",
    )
    parser.add_argument(
        "--app-url",
        default=os.environ.get("APP_URL", "http://localhost:8080"),
        help="Issuer URL for JWT 'iss' claim (e.g., https://auth.example.com)",
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
        "--rsa-private-key",
        default=os.environ.get("OAUTH_RSA_PRIVATE_KEY"),
        help="RSA private key file path for RS*/PS* algorithms",
    )
    serve_parser.add_argument(
        "--ec-p256-private-key",
        default=os.environ.get("OAUTH_EC_P256_PRIVATE_KEY"),
        help="ECDSA P-256 private key file path for ES256",
    )
    serve_parser.add_argument(
        "--ec-p384-private-key",
        default=os.environ.get("OAUTH_EC_P384_PRIVATE_KEY"),
        help="ECDSA P-384 private key file path for ES384",
    )
    serve_parser.add_argument(
        "--ec-p521-private-key",
        default=os.environ.get("OAUTH_EC_P521_PRIVATE_KEY"),
        help="ECDSA P-521 private key file path for ES512",
    )
    serve_parser.add_argument(
        "--eddsa-private-key",
        default=os.environ.get("OAUTH_EDDSA_PRIVATE_KEY"),
        help="Ed25519 private key file path for EdDSA",
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

    # clients command
    clients_parser = subparsers.add_parser("clients", help="Manage OAuth clients")
    clients_subparsers = clients_parser.add_subparsers(
        dest="clients_command", help="Client commands"
    )

    # clients create
    create_parser = clients_subparsers.add_parser("create", help="Create a new client")
    create_parser.add_argument(
        "-i",
        "--id",
        "--client-id",
        dest="client_id",
        help="Client identifier (auto-generated if omitted, and must be unique)",
    )
    create_parser.add_argument(
        "-s",
        "--client-secret",
        dest="client_secret",
        help="Client secret (password for obtaining tokens). Supports @file, base64:, 0x formats. If omitted, a random 32-byte secret will be generated.",
    )
    create_parser.add_argument(
        "-a",
        "--alg",
        "--algorithm",
        dest="algorithm",
        default="HS256",
        choices=[alg.name for alg in SymmetricAlgorithm]
        + [alg.name for alg in AsymmetricAlgorithm],
        help="JWT signing algorithm the client wants (default: HS256)",
    )
    create_parser.add_argument(
        "--signing-secret",
        dest="signing_secret",
        help="Signing secret for HMAC algorithms (required for HS*). Supports @file, base64:, 0x formats. If omitted, a random 32-byte secret will be generated.",
    )
    create_parser.add_argument(
        "-c",
        "--scope",
        dest="scopes",
        action="append",
        help="Add scope to the client's allowed scopes (can be specified multiple times or as a comma-separated list)",
    )
    create_parser.add_argument(
        "-u",
        "--aud",
        "--audience",
        dest="audiences",
        action="append",
        help="Add allowed audience to the client's allowed audiences (can be specified multiple times or as a comma-separated list)",
    )

    # clients list
    _list_parser = clients_subparsers.add_parser("list", help="List all clients")
    # TODO: Add filters?

    # clients delete
    delete_parser = clients_subparsers.add_parser("delete", help="Delete a client")
    delete_parser.add_argument(
        "-d", "--client-id", required=True, help="Client identifier"
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


def _normalize_key_path(value: str | None) -> str | None:
    """Normalize a private key CLI value to a parse_secret-compatible string.

    If the value is already prefixed (@, base64:, 0x, hex:) or looks like
    inline PEM, it is returned as-is. Otherwise it is treated as a file path
    and prefixed with '@' so that parse_secret reads it from disk.
    """
    if value is None:
        return None
    if value.startswith(("@", "base64:", "0x", "hex:")):
        return value
    if value.startswith("-----"):
        # Inline PEM string
        return value
    # Treat as file path
    return f"@{value}"


def _cmd_serve(args: argparse.Namespace) -> int:
    """Handle the 'serve' command."""
    from basic_oauth2_server.server import run_server

    config = ServerConfig(
        host=args.host,
        port=args.port,
        db_path=args.db,
        app_url=args.app_url,
        rsa_private_key=_normalize_key_path(args.rsa_private_key),
        ec_p256_private_key=_normalize_key_path(args.ec_p256_private_key),
        ec_p384_private_key=_normalize_key_path(args.ec_p384_private_key),
        ec_p521_private_key=_normalize_key_path(args.ec_p521_private_key),
        eddsa_private_key=_normalize_key_path(args.eddsa_private_key),
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
        create_args = ClientCreateArgs(
            client_id=args.client_id,
            client_secret=args.client_secret,
            algorithm=args.algorithm,
            signing_secret=args.signing_secret,
            scopes=args.scopes,
            audiences=args.audiences,
            db=args.db,
        )
        return _cmd_clients_create(create_args)
    elif args.clients_command == "list":
        return _cmd_clients_list(args)
    elif args.clients_command == "delete":
        return _cmd_clients_delete(args)

    return 0


# Define namespace with proper types for client creation arguments
class ClientCreateArgs(argparse.Namespace):
    client_id: str | None
    client_secret: str | None
    algorithm: str
    signing_secret: str | None
    scopes: list[str] | None
    audiences: list[str] | None
    db: str


def _cmd_clients_create(args: ClientCreateArgs) -> int:
    """Handle 'clients create' command."""

    algorithm = get_algorithm(args.algorithm) or SymmetricAlgorithm.HS256

    client_secret = (
        decode_prefixed_utf8(args.client_secret)
        if args.client_secret
        else secrets.token_bytes(32)
    )

    signing_secret = (
        (
            decode_prefixed_utf8(args.signing_secret)
            if args.signing_secret
            else secrets.token_bytes(32)
        )
        if algorithm and is_symmetric(algorithm)
        else None
    )

    scopes = args.scopes or []
    audiences = args.audiences or []

    client = create_client(
        db_path=args.db,
        client_id=args.client_id or str(uuid.uuid4()),
        client_secret=client_secret,
        algorithm=algorithm,
        signing_secret=signing_secret,
        scopes=scopes,
        audiences=audiences,
    )

    print(f"OAUTH_CLIENT_ID={client.client_id}")
    if not args.client_secret and client_secret:
        # print if we auto-generated the client secret, but not if it was provided by the user
        print(f"OAUTH_CLIENT_SECRET={base64.b64encode(client_secret).decode()}")
    if is_symmetric(algorithm) and not args.signing_secret and signing_secret:
        # print if we auto-generated the signing secret, but not if it was provided by the user
        print(f"JWT_ALGORITHM={algorithm.name}")
        print(f'JWT_SECRET="hex:{signing_secret.hex()}"')

    return 0


def _cmd_clients_list(args: argparse.Namespace) -> int:
    """Handle 'clients list' command."""
    clients = list_clients(args.db)

    if not clients:
        print("No clients found.")
        return 0

    print(
        f"{'Client ID':<36} {'Algorithm':<10} {'Scopes':<15} {'Audiences':<15} {'Last Used'}"
    )
    print("-" * (36 + 10 + 15 + 15 + 20 + 4))
    for client in clients:
        scopes = client.scopes or "(none)"
        audiences = client.audiences or "(none)"
        last_used = (
            client.last_used_at.strftime("%Y-%m-%d %H:%M")
            if client.last_used_at
            else "(never)"
        )
        print(
            f"{client.client_id:<36} {client.algorithm:<10} {scopes:<15} {audiences:<15} {last_used}"
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

    config = AdminConfig(
        app_url=args.app_url,
        host=args.host,
        port=args.port,
        db_path=args.db,
    )

    print(f"Starting admin dashboard on {config.host}:{config.port}")
    run_admin(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
