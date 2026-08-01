"""Database models and operations using SQLAlchemy."""

import base64
import bcrypt
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from jws_algorithms import SymmetricAlgorithm
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    create_engine,
    delete,
    event,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from basic_oauth2_server.config import ServerConfig, get_app_key
from basic_oauth2_server.crypto import decrypt_from_base64, encrypt_to_base64
from basic_oauth2_server.exceptions import InvalidGrantException
from basic_oauth2_server.jwt import Algorithm, create_access_token, get_algorithm

logger = logging.getLogger(__name__)


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
    """OAuth 2.0 client model."""

    __tablename__ = "clients"

    title: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # The unique client identifier (public). This is the "username" for a client itself (not the user).
    client_id: Mapped[str] = mapped_column(String(255), primary_key=True, unique=True)
    # HMAC-SHA256 (keyed with APP_KEY) of the client secret. The "password" used to obtain access tokens.
    # All clients must have a secret. Public clients are not supported by design.
    # TODO: `set_secret` sets the value as hex, maybe there's a better way to store and retrieve this value other than as string with documentation?
    client_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Algorithm used to sign JWTs for this client (HS256, RS256, EdDSA, etc.).
    # The client chooses based on their verification capabilities.
    # TODO: Does sqlalchmey support Mapped of Enums? A string doesn't feel too nice.
    algorithm: Mapped[str] = mapped_column(String(20), default="HS256")
    # AES-encrypted signing secret (for symmetric/HMAC algorithms only).
    # TODO: Does the db actually not have a way to store these besides Text/string? Same with the secret above. I guess the getter/setter ingest/emit bytes and internally fully handle them as base64, its fine, as bytes for secrets is usually clear.
    encrypted_signing_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Comma-separated list of allowed scopes.
    scopes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Comma-separated list of allowed audiences.
    audiences: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Timestamp of last successful token issuance.
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Comma-separated list of authorized redirect URIs for the authorization code flow.
    redirect_uris: Mapped[str | None] = mapped_column(Text, nullable=True)

    def verify_client_secret(self, user_secret: str | bytes) -> bool:
        """Verify that the provided secret matches the stored HMAC hash.

        Accepts the secret as either a base64-encoded string (as returned by
        the CLI) or raw bytes. Returns True on a match, False otherwise.

        TODO: The parameter str | bytes maybe should be expressed as a newtype instead of documentation.
        """
        if not self.client_secret:
            return False

        if isinstance(user_secret, str):
            try:
                decoded_secret = base64.b64decode(user_secret, validate=True)
            except Exception:
                decoded_secret = None

            if decoded_secret is not None:
                decoded_mac = hmac.digest(get_app_key(), decoded_secret, "sha256").hex()
                if hmac.compare_digest(self.client_secret, decoded_mac):
                    return True

            user_secret = user_secret.encode("utf-8")

        mac = hmac.digest(get_app_key(), user_secret, "sha256").hex()
        return hmac.compare_digest(self.client_secret, mac)

    def set_secret(self, secret: bytes) -> None:
        """Compute and store HMAC-SHA256 of the client secret, keyed with APP_KEY."""
        self.client_secret = hmac.digest(get_app_key(), secret, "sha256").hex()

    def get_signing_secret(self) -> bytes | None:
        """Decrypt and return the signing secret (for HMAC algorithms). Returns None if not set."""
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
        return [scope.strip() for scope in self.scopes.split(",") if scope.strip()]

    def get_audiences_list(self) -> list[str]:
        """Return audiences as a list."""
        if not self.audiences:
            return []
        return [
            audience.strip()
            for audience in self.audiences.split(",")
            if audience.strip()
        ]

    def get_redirect_uris_list(self) -> list[str]:
        """Return redirect URIs as a list."""
        if not self.redirect_uris:
            return []
        return [uri.strip() for uri in self.redirect_uris.split(",") if uri.strip()]

    def get_signing_secret_fingerprint(self) -> str | None:
        """Return a short SHA256 fingerprint of the signing secret with a `sha256:` prefix, or None if not set."""
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
        password_bytes = hashlib.sha256(password.encode()).digest()
        self.password_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode()

    def verify_password(self, password: str) -> bool:
        """Verify that the provided password matches the stored hash."""
        password_bytes = hashlib.sha256(password.encode()).digest()
        return bcrypt.checkpw(password_bytes, self.password_hash.encode())


Index("ix_users_username", User.username, unique=True)


class AuthorizationCode(TimestampMixin, Base):
    """Stored authorization code for the authorization_code grant flow."""

    __tablename__ = "authorization_codes"

    code: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False)
    user_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("users.username"), nullable=False
    )
    redirect_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Space-separated scopes granted by the user.
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    audience: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    # code_challenge is base64url(SHA-256(code_verifier)), verified at token exchange.
    code_challenge: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Only "S256" is supported.
    code_challenge_method: Mapped[str] = mapped_column(
        String(10), default="S256", nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    consent_jti: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)


Index("ix_auth_codes_client_id", AuthorizationCode.client_id)


class RefreshToken(Base):
    """Stored opaque refresh token for the refresh_token grant flow."""

    __tablename__ = "refresh_tokens"

    token: Mapped[str] = mapped_column(String(128), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("clients.client_id"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("users.username"), nullable=False
    )
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    audience: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


Index("ix_refresh_tokens_client_id", RefreshToken.client_id)
Index("ix_refresh_tokens_user_id", RefreshToken.user_id)


class DbSession:
    """Typed wrapper around a SQLAlchemy Session."""

    def __init__(self, session: Session) -> None:
        """Store the SQLAlchemy session."""
        self._session = session

    def __enter__(self) -> "DbSession":
        """Return the wrapped session context."""
        logger.debug("DB session opened (%d)", id(self._session))
        return self

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Close the underlying SQLAlchemy session."""
        if exc_type is not None:
            logger.debug(
                "DB session closed with exception (%d): %s",
                id(self._session),
                exc_type.__name__,
            )
        else:
            logger.debug("DB session closed (%d)", id(self._session))
        self._session.close()


class ClientRepository:
    """Repository for OAuth client persistence."""

    def __init__(self, db: DbSession) -> None:
        """Store the database session wrapper."""
        self._db = db

    def get(self, client_id: str) -> Client | None:
        """Retrieve a client by ID."""
        return self._db._session.get(Client, client_id)

    def create(
        self,
        client_id: str,
        algorithm: Algorithm,
        client_secret: bytes | None = None,
        signing_secret: bytes | None = None,
        scopes: list[str] | None = None,
        audiences: list[str] | None = None,
        redirect_uris: list[str] | None = None,
        title: str | None = None,
    ) -> Client:
        """Create and persist a new OAuth client.

        Args:
            client_id: Unique client identifier.
            algorithm: JWT signing algorithm (HS256, RS256, EdDSA, etc.).
            client_secret: Raw secret bytes, stored as an HMAC hash.
            signing_secret: Signing secret for HMAC algorithms, stored encrypted.
            scopes: Allowed scopes.
            audiences: Allowed audiences.
            redirect_uris: Allowed redirect URIs for the authorization code flow.
            title: Human-readable display name (defaults to client_id).
        """
        client = Client(
            client_id=client_id,
            title=title or client_id,
            algorithm=algorithm.name,
            scopes=",".join(scopes) if scopes else None,
            audiences=",".join(audiences) if audiences else None,
            redirect_uris=",".join(redirect_uris) if redirect_uris else None,
        )
        if client_secret is not None:
            client.set_secret(client_secret)
        if signing_secret is not None:
            client.set_signing_secret(signing_secret)

        self._db._session.add(client)
        self._db._session.commit()
        self._db._session.refresh(client)
        logger.info("Client created: %s (algorithm=%s)", client_id, algorithm.name)
        return client

    def list(self) -> list[Client]:
        """Return all clients."""
        return list(self._db._session.query(Client).all())

    def delete(self, client_id: str) -> bool:
        """Delete a client by ID. Returns True if deleted, False if not found."""
        client = self._db._session.get(Client, client_id)
        if client is None:
            logger.warning("Client not found for deletion: %s", client_id)
            return False
        self._db._session.delete(client)
        self._db._session.commit()
        logger.info("Client deleted: %s", client_id)
        return True

    def touch_last_used(self, client_id: str) -> None:
        """Update the client's last-used timestamp."""
        client = self._db._session.get(Client, client_id)
        if client is not None:
            client.last_used_at = datetime.now(timezone.utc)
            self._db._session.commit()
            logger.debug("Client last_used updated: %s", client_id)


class UserRepository:
    """Repository for OAuth resource owner persistence."""

    def __init__(self, db: DbSession) -> None:
        """Store the database session wrapper."""
        self._db = db

    def get(self, username: str) -> User | None:
        """Retrieve a user by username."""
        return self._db._session.get(User, username)

    def create(self, username: str, password: str) -> User:
        """Create and persist a user."""
        user = User(username=username, password_hash="")
        user.set_password(password)
        self._db._session.add(user)
        self._db._session.commit()
        self._db._session.refresh(user)
        logger.info("User created: %s", username)
        return user

    def list(self) -> list[User]:
        """Return all users."""
        return list(self._db._session.query(User).all())

    def delete(self, username: str) -> bool:
        """Delete a user by username. Returns True if deleted, False if not found."""
        user = self._db._session.get(User, username)
        if user is None:
            logger.warning("User not found for deletion: %s", username)
            return False
        self._db._session.delete(user)
        self._db._session.commit()
        logger.info("User deleted: %s", username)
        return True

    def update_password(self, username: str, password: str) -> bool:
        """Update a user's password. Returns True if updated, False if the user was not found."""
        user = self._db._session.get(User, username)
        if user is None:
            logger.warning("User not found for password update: %s", username)
            return False
        user.set_password(password)
        user.updated_at = datetime.now(timezone.utc)
        self._db._session.commit()
        logger.info("Password updated for user: %s", username)
        return True


class TokenRepository:
    """Repository for authorization codes, refresh tokens, and token issuance."""

    def __init__(self, db: DbSession, config: ServerConfig) -> None:
        """Store the database session wrapper and server config."""
        self._db = db
        self._config = config

    @property
    def token_expires_in(self) -> int:
        """Return the configured access-token lifetime."""
        return self._config.token_expires_in

    def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str | None,
        scope: str | None,
        audience: str | None,
        state: str | None,
        code_challenge: str | None,
        consent_jti: str,
        code_challenge_method: str = "S256",
        expires_in: int = 600,
    ) -> str:
        """Create and persist a new authorization code.

        Args:
            consent_jti: The JTI of the consent token that authorized this code.
                Stored with a UNIQUE constraint so that replaying the same consent
                token a second time is rejected rather than silently creating a
                second code.
        """
        if not consent_jti:
            raise ValueError("consent_jti is required to create an authorization code")

        code = secrets.token_urlsafe(48)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
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
            consent_jti=consent_jti,
        )
        try:
            self._db._session.add(auth_code)
            self._db._session.commit()
        except IntegrityError as exc:
            self._db._session.rollback()
            logger.warning("Consent token replay for jti=%s", consent_jti)
            raise InvalidGrantException("Consent token already used") from exc
        logger.info(
            "Authorization code created for client=%s user=%s", client_id, user_id
        )
        return code

    def consume_authorization_code(self, code: str) -> AuthorizationCode | None:
        """Atomically mark an authorization code as used and return it."""
        now = datetime.now(timezone.utc)
        returned_code = self._db._session.execute(
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
            logger.debug("Authorization code not found or invalid: %.8s...", code)
            return None
        self._db._session.commit()
        logger.info("Authorization code consumed: %.8s...", code)
        return self._db._session.get(AuthorizationCode, returned_code)

    def get_authorization_code(self, code: str) -> AuthorizationCode | None:
        """Retrieve an authorization code by value."""
        return self._db._session.get(AuthorizationCode, code)

    def prune_authorization_codes(self) -> int:
        """Delete used or expired authorization code rows. Returns the number deleted."""
        now = datetime.now(timezone.utc)
        prune_predicate = or_(
            AuthorizationCode.used.is_(True),
            AuthorizationCode.expires_at < now,
        )
        deleted_count = self._db._session.scalar(
            select(func.count()).select_from(AuthorizationCode).where(prune_predicate)
        )
        self._db._session.execute(delete(AuthorizationCode).where(prune_predicate))
        self._db._session.commit()
        logger.info("Pruned %d authorization codes", int(deleted_count or 0))
        return int(deleted_count or 0)

    def consume_refresh_token(self, token: str) -> RefreshToken | None:
        """Atomically retrieve and delete a refresh token if still valid.

        TODO: Consider requiring client_id here as an extra binding check.

        Returns the deleted row when the token exists and has not expired,
        otherwise None.
        """
        now = datetime.now(timezone.utc)
        deleted_token_row = (
            self._db._session.execute(
                delete(RefreshToken)
                .where(
                    RefreshToken.token == token,
                    RefreshToken.expires_at > now,
                )
                .returning(
                    RefreshToken.token,
                    RefreshToken.client_id,
                    RefreshToken.user_id,
                    RefreshToken.scope,
                    RefreshToken.audience,
                    RefreshToken.expires_at,
                    RefreshToken.created_at,
                )
            )
            .mappings()
            .one_or_none()
        )
        self._db._session.commit()
        if deleted_token_row is None:
            logger.debug("Refresh token not found or expired: %.8s...", token)
            return None
        logger.info(
            "Refresh token consumed for client=%s user=%s",
            deleted_token_row["client_id"],
            deleted_token_row["user_id"],
        )
        return RefreshToken(**deleted_token_row)

    def delete_refresh_token(self, token: str) -> bool:
        """Delete a refresh token by value. Returns True if deleted, False if not found."""
        refresh_token = self._db._session.get(RefreshToken, token)
        if refresh_token is None:
            return False
        self._db._session.delete(refresh_token)
        self._db._session.commit()
        logger.info("Refresh token deleted: %.8s...", token)
        return True

    def prune_refresh_tokens(self) -> int:
        """Delete expired refresh token rows. Returns the number deleted."""
        now = datetime.now(timezone.utc)
        prune_predicate = RefreshToken.expires_at < now
        deleted_count = self._db._session.scalar(
            select(func.count()).select_from(RefreshToken).where(prune_predicate)
        )
        self._db._session.execute(delete(RefreshToken).where(prune_predicate))
        self._db._session.commit()
        logger.info("Pruned %d refresh tokens", int(deleted_count or 0))
        return int(deleted_count or 0)

    def issue_access_token(
        self,
        client: Client,
        subject: str,
        scopes: list[str] | None,
        audience: str | list[str] | None,
    ) -> str:
        """Sign and return a JWT access token for the given client.

        Uses the client's configured algorithm. Symmetric algorithms sign with
        the client's stored signing secret. Asymmetric algorithms use the
        server's private key for the algorithm family.
        """
        algorithm = get_algorithm(client.algorithm)
        if isinstance(algorithm, SymmetricAlgorithm):
            signing_secret = client.get_signing_secret()
            if signing_secret is None:
                raise ValueError(
                    f"Client '{client.client_id}' has no signing secret configured"
                )
            token = create_access_token(
                subject=subject,
                algorithm=algorithm,
                secret=signing_secret,
                scopes=scopes,
                audience=audience,
                expires_in=self._config.token_expires_in,
                issuer=self._config.app_url,
                client_id=client.client_id,
            )
        else:
            private_key, kid = self._config.load_private_key(algorithm)
            token = create_access_token(
                subject=subject,
                algorithm=algorithm,
                private_key=private_key,
                scopes=scopes,
                audience=audience,
                expires_in=self._config.token_expires_in,
                kid=kid,
                issuer=self._config.app_url,
                client_id=client.client_id,
            )
        logger.info(
            "Access token issued for client=%s subject=%s (alg=%s)",
            client.client_id,
            subject,
            client.algorithm,
        )
        return token

    def issue_refresh_token(
        self,
        client: Client,
        user_id: str,
        scopes: list[str] | None,
        audience: str | list[str] | None,
    ) -> str:
        """Persist and return a new opaque refresh token.

        The token is a random URL-safe string, not a JWT. It is bound to the
        client and user and expires after config.refresh_token_expires_in seconds.
        """
        token = secrets.token_urlsafe(48)
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=self._config.refresh_token_expires_in
        )
        self._db._session.add(
            RefreshToken(
                token=token,
                client_id=client.client_id,
                user_id=user_id,
                scope=" ".join(scopes) if scopes else None,
                audience=" ".join(audience) if isinstance(audience, list) else audience,
                expires_at=expires_at,
            )
        )
        self._db._session.commit()
        logger.info(
            "Refresh token issued for client=%s user=%s (expires_in=%ds)",
            client.client_id,
            user_id,
            self._config.refresh_token_expires_in,
        )
        return token


def _set_sqlite_pragma(dbapi_connection: object, _connection_record: object) -> None:
    """Set SQLite pragmas for better performance and safety."""
    # TODO: Fix `object has no attribute "cursor"`
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.execute("PRAGMA journal_mode = WAL")
    cursor.execute("PRAGMA synchronous = NORMAL")
    cursor.execute("PRAGMA temp_store = MEMORY")
    cursor.execute("PRAGMA busy_timeout = 5000")
    cursor.close()


class Database:
    """Manage the configured SQLAlchemy engine and sessions."""

    def __init__(self) -> None:
        """Initialize an unconfigured database wrapper."""
        self._db_path: str | None = None
        self._engine: Engine | None = None
        self._session_factory: sessionmaker[Session] | None = None

    def configure(self, db_path: str) -> None:
        """Configure the database engine and session factory."""
        if self._db_path == db_path and self._session_factory is not None:
            return

        if self._engine is not None:
            self._engine.dispose()

        engine = create_engine(f"sqlite:///{db_path}", echo=False)
        if engine.dialect.name == "sqlite":
            event.listen(engine, "connect", _set_sqlite_pragma)
        Base.metadata.create_all(engine)

        self._db_path = db_path
        self._engine = engine
        self._session_factory = sessionmaker(bind=engine)
        logger.info("Database configured: %s", db_path)

    def connect(self) -> DbSession:
        """Return a new database session wrapper."""
        if self._session_factory is None:
            raise RuntimeError(
                "Database not configured. Call database.configure(db_path) first."
            )
        logger.debug("New DB session created")
        return DbSession(self._session_factory())

    def reset(self) -> None:
        """Dispose the configured engine and clear cached state."""
        if self._engine is not None:
            self._engine.dispose()
        self._db_path = None
        self._engine = None
        self._session_factory = None
        logger.info("Database reset")


database = Database()


def init_db(db_path: str) -> None:
    """Initialize the configured database, creating tables if needed.
    TODO: A global `database` object with global configuration is stupid. `init_db` should be removed and the global `database` object should be created and explicitly passed to where it is needed.
    """
    database.configure(db_path)
