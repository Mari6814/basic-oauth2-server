"""Database models and operations using SQLAlchemy."""

import base64
import bcrypt
from functools import lru_cache
import hashlib
from datetime import datetime, timedelta, timezone
import secrets

from sqlalchemy import (
    Boolean,
    DateTime,
    String,
    Text,
    create_engine,
    Index,
    event,
    update,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from basic_oauth2_server.config import get_app_key
from basic_oauth2_server.crypto import decrypt_from_base64, encrypt_to_base64
from basic_oauth2_server.jwt import Algorithm


class Base(DeclarativeBase):
    """Base class for SQLAlchemy models."""

    pass


class TimestampMixin:
    """Mixin that adds auto-managed created_at and updated_at columns."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class Client(TimestampMixin, Base):
    """OAuth2.0 client model."""

    __tablename__ = "clients"

    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # The unique client identifier (public). This is the "username" for a client itself (not the user)
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
    # Comma-separated list of authorized redirect URIs for authorization code flow
    redirect_uris: Mapped[str | None] = mapped_column(Text, nullable=True)

    def verify_client_secret(self, user_secret: str | bytes) -> bool:
        """Verify that the provided secret matches the stored hash.

        Compares the provided user input with the stored hash of the client
        secret and returns True if they match, False otherwise.

        Args:
            user_secret: The client secret provided by the user, either as a base64-encoded string or bytes.

        Returns:
            bool: True if the provided secret is correct, False otherwise.
        """
        if not self.client_secret:
            return False
        if isinstance(user_secret, str):
            try:
                user_secret = base64.b64decode(user_secret, validate=True)
            except Exception:
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

    def get_audiences_list(self) -> list[str]:
        """Return audiences as a list."""
        if not self.audiences:
            return []
        return [a.strip() for a in self.audiences.split(",") if a.strip()]

    def get_redirect_uris_list(self) -> list[str]:
        """Return redirect URIs as a list."""
        if not self.redirect_uris:
            return []
        return [u.strip() for u in self.redirect_uris.split(",") if u.strip()]

    def get_signing_secret_fingerprint(self) -> str | None:
        """Return a short SHA256 fingerprint for the signing secret with prefix."""
        secret = self.get_signing_secret()
        if not secret:
            return None
        return f"sha256:{hashlib.sha256(secret).hexdigest()}"


class User(TimestampMixin, Base):
    """User model for authorization."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(255), primary_key=True, unique=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    def set_password(self, password: str) -> None:
        """Hash and store the password using bcrypt."""
        self.password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password: str) -> bool:
        """Verify that the provided password matches the stored hash."""
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())


Index("ix_users_username", User.username, unique=True)


class AuthorizationCode(TimestampMixin, Base):
    """Stores authorization codes for the authorization_code grant flow."""

    __tablename__ = "authorization_codes"

    code: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # TODO: The user who authorized the request (from Basic Auth). Should be a foreign key to the new users table?
    user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    redirect_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Space-separated scopes
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    audience: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    # PKCE: code_challenge and method (only S256 is supported)
    code_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    code_challenge_method: Mapped[str] = mapped_column(
        String(10), default="S256", nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


Index("ix_auth_codes_client_id", AuthorizationCode.client_id)


def create_authorization_code(
    db_path: str,
    client_id: str,
    user_id: str,
    redirect_uri: str | None,
    scope: str | None,
    audience: str | None,
    state: str | None,
    code_challenge: str | None,
    code_challenge_method: str = "S256",
    expires_in: int = 600,
) -> str:
    """Create and store a new authorization code. Returns the code string."""
    code = secrets.token_urlsafe(48)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    with get_session(db_path) as session:
        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            audience=audience,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
        )
        session.add(auth_code)
        session.commit()
    return code


def consume_authorization_code(db_path: str, code: str) -> AuthorizationCode | None:
    """In one atomic action, retrieve an authorization code and mark it as used. Returns the code if valid and unused, or None if invalid, expired, or already used."""
    now = datetime.now(timezone.utc)
    with get_session(db_path) as session:
        returned_code = session.execute(
            update(AuthorizationCode)
            .where(
                AuthorizationCode.code == code,
                AuthorizationCode.used == False,  # noqa: E712
                AuthorizationCode.expires_at > now,
            )
            .values(used=True)
            .returning(AuthorizationCode.code)
        ).scalar()
        if returned_code is None:
            return None
        session.commit()
        return session.get(AuthorizationCode, returned_code)


def get_authorization_code(db_path: str, code: str) -> AuthorizationCode | None:
    """Retrieve an authorization code record by code."""
    with get_session(db_path) as session:
        return session.get(AuthorizationCode, code)


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


@lru_cache
def get_engine(db_path: str):
    """Create and cache a SQLAlchemy engine for the given database path and apply SQLite pragmas."""
    engine = create_engine(f"sqlite:///{db_path}", echo=False)

    if engine.dialect.name == "sqlite":
        event.listens_for(engine, "connect")(_set_sqlite_pragma)

    return engine


@lru_cache
def get_sessionmaker(db_path: str):
    """Create and cache a sessionmaker, initializing the DB schema on first call."""
    engine = get_engine(db_path)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def init_db(db_path: str) -> None:
    """Initialize the database, creating tables if needed. Idempotent."""
    get_sessionmaker(db_path)


def get_session(db_path: str) -> Session:
    """Get a new database session."""
    return get_sessionmaker(db_path)()


def get_client(db_path: str, client_id: str) -> Client | None:
    """Retrieve a client by ID."""
    with get_session(db_path) as session:
        return session.get(Client, client_id)


def create_client(
    db_path: str,
    client_id: str,
    algorithm: Algorithm,
    client_secret: bytes | None = None,
    signing_secret: bytes | None = None,
    scopes: list[str] | None = None,
    audiences: list[str] | None = None,
    redirect_uris: list[str] | None = None,
    title: str | None = None,
) -> Client:
    """Create a new OAuth client.

    Args:
        db_path: Path to the database.
        client_id: Unique client identifier.
        client_secret: Client secret ("password") for OAuth authentication.
        algorithm: JWT signing algorithm the client wants (HS256, RS256, EdDSA, etc.).
        signing_secret: Signing secret for HMAC algorithms (required for HS256, etc.).
        scopes: List of allowed scopes.
        audiences: List of allowed audiences.
        redirect_uris: List of allowed redirect URIs for authorization code flow.
        title: Display title for the client (defaults to client_id).
    """
    with get_session(db_path) as session:
        client = Client(
            client_id=client_id,
            title=title or client_id,
            algorithm=algorithm.name,
            scopes=",".join(scopes) if scopes else None,
            audiences=",".join(audiences) if audiences else None,
            redirect_uris=",".join(redirect_uris) if redirect_uris else None,
        )
        if client_secret:
            client.set_secret(client_secret)
        if signing_secret:
            client.set_signing_secret(signing_secret)

        session.add(client)
        session.commit()
        session.refresh(client)
        return client


def touch_client_last_used(db_path: str, client_id: str) -> None:
    """Update the last_used_at timestamp for a client."""
    with get_session(db_path) as session:
        client = session.get(Client, client_id)
        if client:
            client.last_used_at = datetime.now(timezone.utc)
            session.commit()


def list_clients(db_path: str) -> list[Client]:
    """List all clients."""
    with get_session(db_path) as session:
        return list(session.query(Client).all())


def delete_client(db_path: str, client_id: str) -> bool:
    """Delete a client by ID. Returns True if deleted, False if not found."""
    with get_session(db_path) as session:
        client = session.get(Client, client_id)
        if client:
            session.delete(client)
            session.commit()
            return True
        return False


def create_user(db_path: str, username: str, password: str) -> User:
    """Create a new user with a bcrypt-hashed password."""
    with get_session(db_path) as session:
        user = User(username=username, password_hash="")
        user.set_password(password)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def get_user(db_path: str, username: str) -> User | None:
    """Retrieve a user by username."""
    with get_session(db_path) as session:
        return session.get(User, username)


def delete_user(db_path: str, username: str) -> bool:
    """Delete a user by username. Returns True if deleted, False if not found."""
    with get_session(db_path) as session:
        user = session.get(User, username)
        if user:
            session.delete(user)
            session.commit()
            return True
        return False


def list_users(db_path: str) -> list[User]:
    """List all users."""
    with get_session(db_path) as session:
        return list(session.query(User).all())


def update_user_password(db_path: str, username: str, new_password: str) -> bool:
    """Update a user's password. Returns True if updated, False if not found."""
    with get_session(db_path) as session:
        user = session.get(User, username)
        if not user:
            return False
        user.set_password(new_password)
        # TODO: Tests have shown that the updated_at timestamp is not updating. Find out what is going on.
        session.commit()
        return True
