# Basic OAuth Authorization Server

A lightweight Python package that implements an OAuth 2.0 client_credentials authorization server. It issues JWT tokens that can be used to authenticate requests to your protected resources.

## Why?

Sometimes you just need a quick and easy way to spin up an OAuth client credentials server for testing, development, or prototyping.
I built this to get more familiar with the OAuth 2.0 spec and to have a simple tool for local development that I understand, because I wrote it.

## Features

- **OAuth 2.0 Client Credentials Flow** - Standard-compliant token endpoint
- **JWT Access Tokens** - Tokens are signed JWTs with configurable algorithms
- **Multiple Signing Algorithms** - Support for HMAC-SHA (HS256, HS384, HS512), RSA (RS256, RS384, RS512), ECDSA (ES256, ES384, ES512), and EdDSA (Ed25519)
- **SQLite Persistence** - Simple file-based database, no external DB required
- **CLI Client Management** - Create and manage clients from the command line
- **Optional Admin Dashboard** - Web UI for client management (localhost-only by default)
- **Single Unified CLI** - One command (`basic-oauth2-server`) for all operations

## Installation

```bash
pip install basic-oauth2-server
```

With admin dashboard:

```bash
pip install basic-oauth2-server[admin]
```

## Quick Start

### 1. Create a client

```bash
# For HMAC algorithms (HS256/384/512), you need a signing secret
basic-oauth2-server clients create \
  --client-id my-app \
  --client-secret my-secret \
  --signing-secret my-signing-key \
  --algorithm HS256
```

### 2. Start the server

```bash
basic-oauth2-server serve --port 8080 --host localhost
```

### 3. Request a token

```bash
curl -X POST http://localhost:8080/oauth/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-app" \
  -d "client_secret=my-secret"
```

## CLI Commands

All functionality is accessed through the `basic-oauth2-server` command:

```
basic-oauth2-server <command> [options]

Commands:
  serve       Start the OAuth authorization server
  clients     Manage OAuth clients (create, list, delete)
  admin       Start the admin dashboard server
```

### serve

Start the main OAuth authorization server.

```bash
basic-oauth2-server serve [options]
```

| Option                  | Environment Variable        | Default      | Description                       |
| ----------------------- | --------------------------- | ------------ | --------------------------------- |
| `--port`                | `OAUTH_PORT`                | `8080`       | Port for the server               |
| `--host`                | `OAUTH_HOST`                | `localhost`  | Host address to bind              |
| `--db`                  | `OAUTH_DB_PATH`             | `./oauth.db` | Path to SQLite database           |
| `--app-url`             | `APP_URL`                   | -            | Issuer URL for JWT `iss` claim    |
| `--rsa-private-key`     | `OAUTH_RSA_PRIVATE_KEY`     | -            | RSA private key for RS256/384/512 |
| `--ec-p256-private-key` | `OAUTH_EC_P256_PRIVATE_KEY` | -            | ECDSA P-256 private key for ES256 |
| `--ec-p384-private-key` | `OAUTH_EC_P384_PRIVATE_KEY` | -            | ECDSA P-384 private key for ES384 |
| `--ec-p521-private-key` | `OAUTH_EC_P521_PRIVATE_KEY` | -            | ECDSA P-521 private key for ES512 |
| `--eddsa-private-key`   | `OAUTH_EDDSA_PRIVATE_KEY`   | -            | Ed25519 private key for EdDSA     |
| `--rsa-key-id`          | `OAUTH_RSA_KEY_ID`          | -            | Key ID for RSA (JWT `kid` header) |
| `--ec-p256-key-id`      | `OAUTH_EC_P256_KEY_ID`      | -            | Key ID for EC P-256 (`kid`)       |
| `--ec-p384-key-id`      | `OAUTH_EC_P384_KEY_ID`      | -            | Key ID for EC P-384 (`kid`)       |
| `--ec-p521-key-id`      | `OAUTH_EC_P521_KEY_ID`      | -            | Key ID for EC P-521 (`kid`)       |
| `--eddsa-key-id`        | `OAUTH_EDDSA_KEY_ID`        | -            | Key ID for EdDSA (`kid`)          |

**Note:** Private keys are only needed if you have clients using that algorithm. Key IDs are optional and will be included in the JWT header as `kid` when specified. Keys can be provided as file paths with `@` prefix (e.g., `@/path/to/key.pem`) or as PEM-encoded strings.

### clients

Manage OAuth clients via the CLI.

```bash
# Create a new client with HMAC-SHA256 (signing secret auto-generated)
basic-oauth2-server clients create \
  --client-id my-service \
  --client-secret supersecret \
  --algorithm HS256
# Output: Generated signing secret: <base64-encoded-secret>

# Or provide your own signing secret
basic-oauth2-server clients create \
  --client-id my-service \
  --client-secret supersecret \
  --signing-secret my-hmac-key \
  --algorithm HS256

# Create a client with RSA signing (server must have --rsa-private-key)
basic-oauth2-server clients create \
  --client-id my-service \
  --client-secret supersecret \
  --algorithm RS256

# Create a client with ECDSA P-256 (server must have --ec-p256-private-key)
basic-oauth2-server clients create \
  --client-id my-service \
  --client-secret supersecret \
  --algorithm ES256

# Create a client with EdDSA (server must have --eddsa-private-key)
basic-oauth2-server clients create \
  --client-id my-service \
  --client-secret supersecret \
  --algorithm EdDSA

# List all clients
basic-oauth2-server clients list

# Delete a client
basic-oauth2-server clients delete --client-id my-service
```

| Option             | Description                                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------------------------------- |
| `--db`             | Path to SQLite database (default: `./oauth.db`)                                                             |
| `--client-id`      | Client identifier                                                                                           |
| `--client-secret`  | Client secret (password for obtaining tokens). Stored as SHA256 hash                                        |
| `--algorithm`      | Signing algorithm: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `EdDSA` |
| `--signing-secret` | Signing secret for HMAC algorithms (auto-generated if not provided for HS256/384/512)                       |
| `--scopes`         | Allowed scopes for this client (comma-separated). Required if client will request scopes                    |
| `--audiences`      | Allowed audiences for this client (comma-separated). Required if client will request audiences              |

### Secret Formats

The `--client-secret`, `--signing-secret`, and private key options all accept values in these formats:

| Prefix    | Format      | Example                |
| --------- | ----------- | ---------------------- |
| `@`       | File path   | `@/path/to/secret.txt` |
| `base64:` | Base64      | `base64:c2VjcmV0...`   |
| `0x`      | Hexadecimal | `0xdeadbeef1234...`    |
| (none)    | Plain text  | `my-secret`            |

Examples:

```bash
# Read secrets from files
basic-oauth2-server clients create \
  --client-id app \
  --client-secret @./client-secret.txt \
  --signing-secret @./signing-key.txt \
  --algorithm HS256

# Base64-encoded secrets
basic-oauth2-server clients create \
  --client-id app \
  --client-secret base64:Y2xpZW50LXNlY3JldA== \
  --signing-secret base64:c2lnbmluZy1rZXk= \
  --algorithm HS256

# Use asymmetric algorithm with private key from file
basic-oauth2-server clients create \
  --client-id app \
  --client-secret mysecret \
  --algorithm RS256

# Then start server with the key
basic-oauth2-server serve --rsa-private-key @./private.pem
```

### admin

Start the optional admin dashboard for managing clients via a web UI.

**Note:** Requires the `admin` extra: `pip install basic-oauth2-server[admin]`

```bash
basic-oauth2-server admin [options]
```

| Option   | Environment Variable | Default      | Description                                           |
| -------- | -------------------- | ------------ | ----------------------------------------------------- |
| `--port` | `OAUTH_ADMIN_PORT`   | `8081`       | Port for admin dashboard                              |
| `--host` | `OAUTH_ADMIN_HOST`   | `localhost`  | Host address (localhost only by default for security) |
| `--db`   | `OAUTH_DB_PATH`      | `./oauth.db` | Path to SQLite database                               |

## Token Endpoint

### POST /oauth/token

Request a new access token.

**Request Parameters:**

| Parameter       | Required | Description                              |
| --------------- | -------- | ---------------------------------------- |
| `grant_type`    | Yes      | Must be `client_credentials`             |
| `client_id`     | Yes      | The client identifier                    |
| `client_secret` | Yes      | The client secret                        |
| `scope`         | No       | Space-separated list of requested scopes |
| `audience`      | No       | Intended audience for the token          |

**Success Response (200 OK):**

```json
{
  "access_token": "ey...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Error Response (400/401):**

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

## Configuration

Configuration can be provided via CLI arguments or environment variables. CLI arguments take precedence.

| Environment Variable        | Description                                          |
| --------------------------- | ---------------------------------------------------- |
| `APP_KEY`                   | Encryption key for sensitive data stored in database |
| `APP_URL`                   | Issuer URL for JWT `iss` claim                       |
| `OAUTH_PORT`                | Main server port                                     |
| `OAUTH_HOST`                | Main server host                                     |
| `OAUTH_DB_PATH`             | SQLite database path                                 |
| `OAUTH_ADMIN_PORT`          | Admin dashboard port                                 |
| `OAUTH_ADMIN_HOST`          | Admin dashboard host                                 |
| `OAUTH_RSA_PRIVATE_KEY`     | RSA private key for RS256/RS384/RS512                |
| `OAUTH_EC_P256_PRIVATE_KEY` | ECDSA P-256 private key for ES256                    |
| `OAUTH_EC_P384_PRIVATE_KEY` | ECDSA P-384 private key for ES384                    |
| `OAUTH_EC_P521_PRIVATE_KEY` | ECDSA P-521 private key for ES512                    |
| `OAUTH_EDDSA_PRIVATE_KEY`   | Ed25519 private key for EdDSA                        |
| `OAUTH_RSA_KEY_ID`          | Key ID for RSA keys (included in JWT `kid` header)   |
| `OAUTH_EC_P256_KEY_ID`      | Key ID for EC P-256 key (JWT `kid` header)           |
| `OAUTH_EC_P384_KEY_ID`      | Key ID for EC P-384 key (JWT `kid` header)           |
| `OAUTH_EC_P521_KEY_ID`      | Key ID for EC P-521 key (JWT `kid` header)           |
| `OAUTH_EDDSA_KEY_ID`        | Key ID for EdDSA key (JWT `kid` header)              |

### APP_KEY

The `APP_KEY` environment variable is required for encrypting sensitive data (such as HMAC signing secrets) before storing them in the SQLite database. Client secrets are stored as SHA256 hashes. This key should be a secure, random string.

Generate a key:

```bash
# Generate a 32-byte base64-encoded key
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Set it before running any command:

```bash
export APP_KEY="your-generated-key-here"
basic-oauth2-server serve
```

**Important:** Keep this key safe. If you lose it, you will not be able to decrypt existing client secrets in the database.

## Examples

### Development Setup with HMAC

```bash
# Create a client with HMAC signing
basic-oauth2-server clients create \
  --client-id dev-client \
  --client-secret dev-secret \
  --signing-secret dev-signing-key

# Start the server
basic-oauth2-server serve

# Get a token
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=dev-client&client_secret=dev-secret"
```

### Production-like Setup with RSA

```bash
# Generate an RSA private key
openssl genrsa -out private.pem 2048

# Create client with RSA signing
basic-oauth2-server clients create \
  --client-id prod-service \
  --client-secret prod-secret \
  --algorithm RS256 \
  --scopes "read,write,admin" \
  --audiences "https://api.example.com"

# Start the server with the RSA private key
basic-oauth2-server serve --rsa-private-key @private.pem
```

### Setup with Multiple Algorithm Support

```bash
# Generate keys for different algorithms
openssl genrsa -out rsa-private.pem 4096
openssl ecparam -name prime256v1 -genkey -noout -out es256-private.pem
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem

# Create clients with different algorithms
basic-oauth2-server clients create --client-id client-rsa --client-secret secret1 --algorithm RS256
basic-oauth2-server clients create --client-id client-ecdsa --client-secret secret2 --algorithm ES256
basic-oauth2-server clients create --client-id client-eddsa --client-secret secret3 --algorithm EdDSA
basic-oauth2-server clients create --client-id client-hmac --client-secret secret4 --algorithm HS256 --signing-secret hmac-key

# Start server with all private keys (optionally with key IDs)
basic-oauth2-server serve \
  --rsa-private-key @rsa-private.pem \
  --rsa-key-id my-rsa-key-1 \
  --ec-p256-private-key @es256-private.pem \
  --ec-p256-key-id my-es256-key-1 \
  --eddsa-private-key @ed25519-private.pem \
  --eddsa-key-id my-eddsa-key-1
```

### Running with Admin Dashboard

```bash
# Terminal 1: Start the main server
basic-oauth2-server serve --port 8080

# Terminal 2: Start the admin dashboard
basic-oauth2-server admin --port 8081

# Access the dashboard at http://localhost:8081
```

### Using Environment Variables

```bash
export APP_KEY="$(openssl rand -base64 32)"
export APP_URL="https://auth.example.com"
export OAUTH_DB_PATH=/var/lib/oauth/oauth.db
export OAUTH_PORT=9000

# Set private keys for each algorithm family you want to support
export OAUTH_RSA_PRIVATE_KEY="@/etc/oauth/rsa-private.pem"
export OAUTH_EC_P256_PRIVATE_KEY="@/etc/oauth/es256-private.pem"
export OAUTH_EC_P384_PRIVATE_KEY="@/etc/oauth/es384-private.pem"
export OAUTH_EC_P521_PRIVATE_KEY="@/etc/oauth/es512-private.pem"
export OAUTH_EDDSA_PRIVATE_KEY="@/etc/oauth/ed25519-private.pem"

# Optionally set key IDs for JWT kid header
export OAUTH_RSA_KEY_ID="rsa-prod-2026"
export OAUTH_EC_P256_KEY_ID="es256-prod-2026"

basic-oauth2-server serve
```

## Future Work

- Support for additional grant types (authorization code, refresh token, etc.)
- Token revocation endpoint (though that only makes sense when using opaque tokens instead of JWTs)

## License

MIT
