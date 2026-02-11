"""Gradio admin dashboard for managing OAuth clients."""

import base64
import logging
import secrets

import gradio as gr

from basic_oauth2_server.config import AdminConfig
from basic_oauth2_server.db import (
    create_client,
    delete_client,
    get_client,
    init_db,
    list_clients,
)
from basic_oauth2_server.jwt import get_algorithm, is_symmetric

logger = logging.getLogger(__name__)


def create_admin_app(config: AdminConfig) -> gr.Blocks:
    """Create the Gradio admin application."""
    init_db(config.db_path)

    def refresh_clients() -> list[list[str]]:
        """Refresh the clients table."""
        clients = list_clients(config.db_path)
        return [
            [
                c.client_id,
                c.algorithm,
                c.get_secret_fingerprint() or "-",
                c.get_signing_secret_fingerprint() or "-",
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
            return "Error: Client ID is required", refresh_clients()

        existing = get_client(config.db_path, client_id)
        if existing:
            return f"Error: Client '{client_id}' already exists", refresh_clients()

        try:
            secret_bytes: bytes | None = None
            if client_secret:
                # Client secret is entered as plain text
                secret_bytes = client_secret.encode("utf-8")

            # Validate signing secret for symmetric algorithms
            signing_secret_bytes: bytes | None = None
            if is_symmetric(get_algorithm(algorithm)):
                if signing_secret:
                    # Signing secret entered as plain text
                    signing_secret_bytes = signing_secret.encode("utf-8")
                else:
                    return (
                        f"Error: Signing secret is required for {algorithm}",
                        refresh_clients(),
                    )

            scopes_list = [s.strip() for s in scopes.split(",") if s.strip()] or None
            audiences_list = [
                a.strip() for a in audiences.split(",") if a.strip()
            ] or None

            create_client(
                db_path=config.db_path,
                client_id=client_id,
                secret=secret_bytes,
                algorithm=algorithm,
                signing_secret=signing_secret_bytes,
                scopes=scopes_list,
                audiences=audiences_list,
            )

            logger.info("Created client via admin: %s", client_id)
            return f"Created client '{client_id}'", refresh_clients()
        except Exception as e:
            return f"Error: {e}", refresh_clients()

    def remove_client(client_id: str) -> tuple[str, list[list[str]]]:
        """Delete a client."""
        if not client_id:
            return "Error: Client ID is required", refresh_clients()

        if delete_client(config.db_path, client_id):
            logger.info("Deleted client via admin: %s", client_id)
            return f"Deleted client '{client_id}'", refresh_clients()
        else:
            return f"Error: Client '{client_id}' not found", refresh_clients()

    def generate_signing_secret() -> str:
        """Generate a new random signing secret."""
        return base64.b64encode(secrets.token_bytes(32)).decode()

    with gr.Blocks(title="OAuth Admin Dashboard") as app:
        gr.Markdown("# OAuth Admin Dashboard")
        gr.Markdown("Manage OAuth 2.0 clients for the authorization server.")

        with gr.Tab("Clients"):
            clients_table = gr.Dataframe(
                headers=[
                    "Client ID",
                    "Algorithm",
                    "Fingerprint",
                    "Signing Fingerprint",
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
                    new_client_id = gr.Textbox(label="Client ID", placeholder="my-app")
                    new_client_secret = gr.Textbox(
                        label="Client Secret",
                        placeholder="Enter plain-text secret",
                        info='Used as the "password" for authenticating with this client.',
                    )
                    new_algorithm = gr.Dropdown(
                        label="Algorithm",
                        choices=[
                            "HS256",
                            "HS384",
                            "HS512",
                            "RS256",
                            "RS384",
                            "RS512",
                            "ES256",
                            "ES384",
                            "ES512",
                            "EdDSA",
                        ],
                        value="HS256",
                        info="JWT signing algorithm the client wants",
                    )
                    new_signing_secret = gr.Textbox(
                        label="Signing Secret (required for HS* algorithms)",
                        placeholder="Click 'Generate' or enter your own",
                        value=generate_signing_secret(),
                        info="Used to sign JWTs. Required for HS256/384/512. Pre-generated for convenience.",
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
                        placeholder="read,write,admin",
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
