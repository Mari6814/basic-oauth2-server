"""Gradio admin dashboard for managing OAuth clients."""

import base64
import secrets
import uuid

from jws_algorithms import AsymmetricAlgorithm, SymmetricAlgorithm
from .secrets import parse_secret

import gradio as gr

from basic_oauth2_server.config import AdminConfig
from basic_oauth2_server.db import (
    Database,
    ClientRepository,
)
from basic_oauth2_server.jwt import get_algorithm


def create_admin_app(config: AdminConfig) -> gr.Blocks:
    """Create the Gradio admin application."""
    db = Database(config.db_path)
    db.create_tables()

    def refresh_clients() -> list[list[str]]:
        """Refresh the clients table."""
        with db.session() as session:
            clients = ClientRepository(session).list_all()
        return [
            [
                c.client_id,
                c.algorithm,
                c.scopes or "",
                (
                    c.last_used_at.strftime("%Y-%m-%d %H:%M")
                    if c.last_used_at
                    else "never used"
                ),
            ]
            for c in clients
        ]

    def add_client(
        client_id: str,
        client_secret: str,
        algorithm: str,
        signing_secret: str,
        scopes: str,
        audiences: str,
    ) -> tuple[str, list[list[str]]]:
        """Add a new client."""

        if not client_id:
            raise ValueError("Client ID is required")

        if not client_secret:
            raise ValueError("Client secret is required")

        client_secret_bytes = parse_secret(client_secret, allow_from_file=False)
        if not client_secret_bytes:
            raise ValueError("Client secret bytes cannot be empty")

        if not algorithm:
            raise ValueError("Algorithm is required")

        algorithm_enum = get_algorithm(algorithm)
        if isinstance(algorithm_enum, SymmetricAlgorithm) and not signing_secret:
            raise ValueError(f"Signing secret is required for {algorithm}")

        signing_secret_bytes: bytes | None = None
        if signing_secret:
            signing_secret_bytes = parse_secret(signing_secret, allow_from_file=False)

        with db.session() as session:
            repo = ClientRepository(session)
            existing = repo.get(client_id)
            if existing:
                return f"Error: Client '{client_id}' already exists", refresh_clients()

            try:
                scopes_list = [
                    s.strip() for s in scopes.split(",") if s.strip()
                ] or None
                audiences_list = [
                    a.strip() for a in audiences.split(",") if a.strip()
                ] or None

                _client = repo.create(
                    client_id=client_id,
                    client_secret=client_secret_bytes,
                    algorithm=algorithm_enum,
                    signing_secret=signing_secret_bytes,
                    scopes=scopes_list,
                    audiences=audiences_list,
                )

                # Convert to base64 for example usage below. Reason: OAuth2 clients typically need to send the secret base64-encoded.
                client_secret_base64 = base64.b64encode(client_secret_bytes).decode()

                msg = "\n".join(
                    [
                        "Environment variables to use this client:",
                        "",
                        f"OAUTH_CLIENT_ID={client_id}",
                        f"OAUTH_CLIENT_SECRET={client_secret_base64}",
                    ]
                    + (
                        [
                            f"JWT_SECRET=base64:{base64.b64encode(signing_secret_bytes).decode()}",
                            f"JWT_ALGORITHM={algorithm_enum.name}",
                        ]
                        if isinstance(algorithm_enum, SymmetricAlgorithm)
                        and signing_secret_bytes
                        else []
                    )
                    + [
                        "",
                        "Example curl command:",
                        "",
                        f"curl {config.app_url or 'APP_URL'}/oauth2/token \\\n"
                        f'\t-u "{client_id}:{client_secret_base64}" \\\n'
                        f'\t-d "grant_type=client_credentials"',
                    ],
                )
                return msg, refresh_clients()
            except Exception as e:
                return f"Error: {e}", refresh_clients()

    def remove_client(client_id: str) -> tuple[str, list[list[str]]]:
        """Delete a client."""
        if not client_id:
            return "Error: Client ID is required", refresh_clients()

        with db.session() as session:
            if ClientRepository(session).delete(client_id):
                return f"Deleted client '{client_id}'", refresh_clients()
            else:
                return f"Error: Client '{client_id}' not found", refresh_clients()

    def generate_signing_secret() -> str:
        """Generate a new random signing secret."""
        return f"base64:{base64.b64encode(secrets.token_bytes(32)).decode()}"

    with gr.Blocks(title="OAuth Admin Dashboard") as app:
        gr.Markdown("# OAuth Admin Dashboard")
        gr.Markdown("Manage OAuth 2.0 clients for the authorization server.")

        with gr.Tab("Clients"):
            clients_table = gr.Dataframe(
                headers=[
                    "Client ID",
                    "Algorithm",
                    "Scopes",
                    "Last used",
                ],
                value=refresh_clients(),
                interactive=False,
            )
            refresh_btn = gr.Button("Refresh")
            refresh_btn.click(fn=refresh_clients, outputs=clients_table)

        with gr.Tab("Add Client"):
            with gr.Row():
                with gr.Column():
                    new_client_id = gr.Textbox(
                        value=str(uuid.uuid4()),
                        label="Client ID",
                        placeholder="my-app",
                    )
                    new_client_secret = gr.Textbox(
                        value=f"base64:{base64.b64encode(secrets.token_bytes(32)).decode()}",
                        label="Client Secret",
                        placeholder="Enter plain-text secret",
                        info='Used as the "password" for authenticating with this client. Use prefix `base64:`, `0x`, or `hex:` for different encodings. Uses utf-8 encoding by default. Note the OAuth2 requires you to send it base64-encoded!',
                    )
                    new_algorithm = gr.Dropdown(
                        label="Algorithm",
                        choices=[alg.name for alg in SymmetricAlgorithm]
                        + [alg.name for alg in AsymmetricAlgorithm],
                        value="HS256",
                        info="JWT signing algorithm the client wants",
                    )
                    new_signing_secret = gr.Textbox(
                        label="Signing Secret (required for HS* algorithms)",
                        placeholder="Click 'Generate' or enter your own",
                        value=generate_signing_secret(),
                        info="Used to sign JWTs. Required for HS256/384/512. Uses utf-8 encoding by default. You can prefix with `base64:`, `hex:`, or `0x` for different encodings.",
                    )
                    generate_secret_btn = gr.Button(
                        "Generate New Signing Secret", size="sm"
                    )
                    generate_secret_btn.click(
                        fn=generate_signing_secret,
                        outputs=new_signing_secret,
                    )
                    new_scopes = gr.Textbox(
                        label="Allowed Scopes",
                        placeholder='for example: "read,write,admin"',
                    )
                    new_audiences = gr.Textbox(
                        label="Allowed Audiences",
                        placeholder="https://api.example.com",
                    )

            add_status = gr.Textbox(label="Status", interactive=False)
            add_btn = gr.Button("Create Client", variant="primary")
            add_btn.click(
                fn=add_client,
                inputs=[
                    new_client_id,
                    new_client_secret,
                    new_algorithm,
                    new_signing_secret,
                    new_scopes,
                    new_audiences,
                ],
                outputs=[add_status, clients_table],
            )

        with gr.Tab("Delete Client"):
            delete_client_id = gr.Textbox(
                label="Client ID to Delete", placeholder="my-app"
            )
            delete_status = gr.Textbox(label="Status", interactive=False)
            delete_btn = gr.Button("Delete Client", variant="stop")
            delete_btn.click(
                fn=remove_client,
                inputs=[delete_client_id],
                outputs=[delete_status, clients_table],
            )

    return app


def run_admin(config: AdminConfig) -> None:
    """Run the admin dashboard with the given configuration."""
    app = create_admin_app(config)
    app.launch(server_name=config.host, server_port=config.port)
