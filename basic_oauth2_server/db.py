"""Database models and operations using SQLAlchemy."""

import hashlib
from datetime import datetime, timezone
import secrets

from sqlalchemy import DateTime, String, Text, create_engine, Index, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from basic_oauth2_server.config import get_app_key
from basic_oauth2_server.crypto import decrypt_from_base64, encrypt_to_base64
from basic_oauth2_server.jwt import Algorithm


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


class Client(Base):
    """OAuth client model."""

    __tablename__ = "clients"

    client_id: Mapped[str] = mapped_column(String(255), primary_key=True, unique=True)
    # SHA256 hexdigest of client secret - the "password" used to obtain access tokens
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

    def verify_client_secret(self, user_secret: bytes) -> bool:
        """Verify that the provided secret matches the stored hash."""
        if not self.client_secret:
            return False
        if secrets.compare_digest(
            self.client_secret, hashlib.sha256(user_secret).hexdigest()
        ):
            return True
        return False

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

    def validate_scopes(self, requested_scopes: list[str]) -> list[str]:
        """Return a list of scopes not allowed for this client."""
        allowed = self.get_scopes_list()
        return [s for s in requested_scopes if s not in allowed]

    def get_audiences_list(self) -> list[str]:
        """Return audiences as a list."""
        if not self.audiences:
            return []
        return [a.strip() for a in self.audiences.split(",") if a.strip()]

    def is_audience_allowed(self, audience: str) -> bool:
        """Check whether the given audience is in this client's allowed list."""
        return audience in self.get_audiences_list()

    def get_signing_secret_fingerprint(self) -> str | None:
        """Return a short SHA256 fingerprint for the signing secret with prefix."""
        secret = self.get_signing_secret()
        if not secret:
            return None
        return f"sha256:{hashlib.sha256(secret).hexdigest()}"


# explicit unique index on client_id (redundant with PK but makes intent clear)
Index("ix_clients_client_id", Client.client_id, unique=True)


def _set_sqlite_pragma(dbapi_connection, connection_record):
    """Event handler for sqlalchemy engine connect event to set SQLite pragmas for better performance and safety."""
    cursor = dbapi_connection.cursor()
    # enforce foreign key constraints
    cursor.execute("PRAGMA foreign_keys = ON")
    # use WAL for better concurrency
    cursor.execute("PRAGMA journal_mode = WAL")
    # reasonable durability vs performance
    cursor.execute("PRAGMA synchronous = NORMAL")
    # keep temp tables in memory
    cursor.execute("PRAGMA temp_store = MEMORY")
    # avoid immediate "database is locked" failures
    cursor.execute("PRAGMA busy_timeout = 5000")
    cursor.close()


class Database:
    """Central database manager.

    Created once at startup.  Holds the engine and session factory so that
    every request can cheaply obtain a new `Session` without recreating
    the connection pool or session maker.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._engine = create_engine(f"sqlite:///{db_path}", echo=False)

        if self._engine.dialect.name == "sqlite":
            event.listens_for(self._engine, "connect")(_set_sqlite_pragma)

        self._session_factory = sessionmaker(bind=self._engine)

    def create_tables(self) -> None:
        """Create all tables if they don't exist."""
        Base.metadata.create_all(self._engine)

    def session(self) -> Session:
        """Create a new database session."""
        return self._session_factory()


class ClientRepository:
    """Repository for Client CRUD operations.

    Accepts a session and provides domain-level operations
    without exposing database internals.
    """

    def __init__(self, session: Session):
        self._session = session

    def get(self, client_id: str) -> Client | None:
        """Retrieve a client by ID."""
        return self._session.get(Client, client_id)

    def create(
        self,
        client_id: str,
        algorithm: Algorithm,
        client_secret: bytes | None = None,
        signing_secret: bytes | None = None,
        scopes: list[str] | None = None,
        audiences: list[str] | None = None,
    ) -> Client:
        """Create a new OAuth client."""
        client = Client(
            client_id=client_id,
            algorithm=algorithm.name,
            scopes=",".join(scopes) if scopes else None,
            audiences=",".join(audiences) if audiences else None,
        )
        if client_secret:
            client.set_secret(client_secret)
        if signing_secret:
            client.set_signing_secret(signing_secret)

        self._session.add(client)
        self._session.commit()
        self._session.refresh(client)
        return client

    def list_all(self) -> list[Client]:
        """List all clients."""
        return list(self._session.query(Client).all())

    def delete(self, client_id: str) -> bool:
        """Delete a client by ID. Returns True if deleted, False if not found."""
        client = self._session.get(Client, client_id)
        if client:
            self._session.delete(client)
            self._session.commit()
            return True
        return False

    def touch_last_used(self, client_id: str) -> None:
        """Update the last_used_at timestamp for a client."""
        client = self._session.get(Client, client_id)
        if client:
            client.last_used_at = datetime.now(timezone.utc)
            self._session.commit()
