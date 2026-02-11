"""Database models and operations using SQLAlchemy."""

import hashlib
import logging
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from basic_oauth2_server.config import get_app_key
from basic_oauth2_server.crypto import decrypt_from_base64, encrypt_to_base64

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


class Client(Base):
    """OAuth client model."""

    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    # SHA256 hash of client secret - the "password" used to obtain access tokens
    client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Algorithm to use for signing (HS256, RS256, EdDSA, etc.)
    # The client chooses based on their verification capabilities
    algorithm: Mapped[str] = mapped_column(String(20), default="HS256")
    # Encrypted signing secret (for symmetric/HMAC algorithms only)
    encrypted_signing_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Comma-separated list of allowed scopes
    scopes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Comma-separated list of allowed audiences
    audiences: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Timestamp of last token issuance
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def verify_secret(self, secret: bytes | str) -> bool:
        """Verify that the provided secret matches the stored hash."""
        if not self.client_secret:
            return False
        if isinstance(secret, str):
            secret = secret.encode("utf-8")
        provided_hash = hashlib.sha256(secret).hexdigest()
        return self.client_secret == provided_hash

    def set_secret(self, secret: bytes) -> None:
        """Hash and store the client secret using SHA256."""
        self.client_secret = hashlib.sha256(secret).hexdigest()

    def get_signing_secret(self) -> bytes | None:
        """Decrypt and return the signing secret (for HMAC algorithms)."""
        if not self.encrypted_signing_secret:
            return None
        return decrypt_from_base64(self.encrypted_signing_secret, get_app_key())

    def set_signing_secret(self, secret: bytes) -> None:
        """Encrypt and store the signing secret."""
        self.encrypted_signing_secret = encrypt_to_base64(secret, get_app_key())

    def get_scopes_list(self) -> list[str]:
        """Return scopes as a list."""
        if not self.scopes:
            return []
        return [s.strip() for s in self.scopes.split(",") if s.strip()]

    def get_audiences_list(self) -> list[str]:
        """Return audiences as a list."""
        if not self.audiences:
            return []
        return [a.strip() for a in self.audiences.split(",") if a.strip()]

    def get_signing_secret_fingerprint(self) -> str | None:
        """Return a short SHA256 fingerprint for the signing secret with prefix.

        Example: "sha256:012345..." (16 hex characters shown after the prefix).
        """
        secret = self.get_signing_secret()
        if not secret:
            return None
        return f"sha256:{hashlib.sha256(secret).hexdigest()[:16]}..."

    def get_secret_fingerprint(self) -> str | None:
        """Return the full SHA256 fingerprint of the client secret with prefix.

        Example: "sha256:012345..." (full 64 hex characters after the prefix).
        """
        if not self.client_secret:
            return None
        return f"sha256:{self.client_secret}"

    def get_secret_hash_truncated(self) -> str | None:
        """Get the first 12 characters of the client secret hash for compact views."""
        if not self.client_secret:
            return None
        return f"{self.client_secret[:12]}..."


def get_engine(db_path: str):
    """Create a SQLAlchemy engine for the given database path."""
    return create_engine(f"sqlite:///{db_path}", echo=False)


def init_db(db_path: str) -> None:
    """Initialize the database, creating tables if needed."""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)


def get_session(db_path: str) -> Session:
    """Get a new database session."""
    engine = get_engine(db_path)
    SessionLocal = sessionmaker(bind=engine)
    return SessionLocal()


def get_client(db_path: str, client_id: str) -> Client | None:
    """Retrieve a client by ID."""
    logger.debug("Retrieving client: %s", client_id)
    with get_session(db_path) as session:
        return session.get(Client, client_id)


def create_client(
    db_path: str,
    client_id: str,
    secret: bytes | None = None,
    algorithm: str = "HS256",
    signing_secret: bytes | None = None,
    scopes: list[str] | None = None,
    audiences: list[str] | None = None,
) -> Client:
    """Create a new OAuth client.

    Args:
        db_path: Path to the database.
        client_id: Unique client identifier.
        secret: Client secret ("password") for OAuth authentication.
        algorithm: JWT signing algorithm the client wants (HS256, RS256, EdDSA, etc.).
        signing_secret: Signing secret for HMAC algorithms (required for HS256, etc.).
        scopes: List of allowed scopes.
        audiences: List of allowed audiences.
    """
    init_db(db_path)
    with get_session(db_path) as session:
        client = Client(
            client_id=client_id,
            algorithm=algorithm,
            scopes=",".join(scopes) if scopes else None,
            audiences=",".join(audiences) if audiences else None,
        )
        if secret:
            client.set_secret(secret)
        if signing_secret:
            client.set_signing_secret(signing_secret)

        session.add(client)
        session.commit()
        session.refresh(client)
        logger.info("Created client: %s with algorithm %s", client_id, algorithm)
        return client


def touch_client_last_used(db_path: str, client_id: str) -> None:
    """Update the last_used_at timestamp for a client."""
    with get_session(db_path) as session:
        client = session.get(Client, client_id)
        if client:
            client.last_used_at = datetime.now(timezone.utc)
            session.commit()
            logger.debug("Updated last_used_at for client: %s", client_id)


def list_clients(db_path: str) -> list[Client]:
    """List all clients."""
    init_db(db_path)
    with get_session(db_path) as session:
        return list(session.query(Client).all())


def delete_client(db_path: str, client_id: str) -> bool:
    """Delete a client by ID. Returns True if deleted, False if not found."""
    with get_session(db_path) as session:
        client = session.get(Client, client_id)
        if client:
            session.delete(client)
            session.commit()
            logger.info("Deleted client: %s", client_id)
            return True
        logger.warning("Client not found for deletion: %s", client_id)
        return False
