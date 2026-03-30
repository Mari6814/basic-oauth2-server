# Basic OAuth Authorization Server

A lightweight python package that implements an OAuth 2.0 authorization server
supporting the client credentials and authorization code (with PKCE) grant
types. It issues JWT tokens that can be used to authenticate requests to your
protected resources.

## Why?

Sometimes you just need a quick and easy way to spin up an OAuth2 authorization
server for testing, development, or prototyping.  I built this to get more
familiar with the OAuth 2.0 spec and to have a simple tool for local development
that I understand, because I wrote it.  Of course you should use something
better like [oauthlib](https://github.com/oauthlib/oauthlib) or anything else
really.

The idea is that the entire configuration is done via CLI arguments. You do not
have to read through a bunch of documentation and just blindly _copy-paste_
random files form evne the official documentation to just get it to work. If you
can read the `--help` output, you can configure this oauth2 provider.

## Overview

- **OAuth 2.0 Client Credentials Flow** - Server-to-server authentication via the token endpoint
- **OAuth 2.0 Authorization Code Flow** - User-delegated access with PKCE (S256, S512, plain)
- **JWT Access Tokens** - Uses JWTs for access tokens that can be configured to include scopes, audiences, custom claims, symmetric or even asymmetric signing algorithms on a per-client basis
- **Multiple Signing Algorithms** - Support for HMAC-SHA (HS256, HS384, HS512), RSA (RS256, RS384, RS512), RSA-PSS (PS256, PS384, PS512), ECDSA (ES256, ES384, ES512), and EdDSA (Ed25519) that can be configured per client, with support for multiple active keys and automatic JWT `kid` header population
- **SQLite Persistence** - Simple file-based database, no external DB required
- **CLI Client & User Management** - Create and manage clients (for client_credentials) and users (for authorization_code) from the command line
- **Optional Admin Dashboard** - Web UI for client and user management (localhost-only by default)
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
A quick example that shows how to create a client, start the server and make a
client_credentials token request.

TLDR: You can run the "serve" command with a default client and user, while
setting up hosting settings and asymmetric signing keys if you have them, all in
one command:

```bash
basic-oauth2-server serve \
  --create-default-client \
  --default-client-id my-app \
  --default-client-secret my-secret \
  --default-client-signing-secret my-signing-key \
  --default-client-algorithm HS256 \
  --default-client-scopes "read write" \
  --default-client-redirect-uris "https://some-app.test/callback" \
  --create-default-user \
  --default-username alice \
  --default-password secret \
  --port 8080 \
  --host localhost
```

### 1. Create a client
Use the `clients` cli to create a new client that can request access to
protected resources via this authorization server.

```bash
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

**Alternatively**, instead of first creating the client, you can use the
*"default client" feature of the "serve" command
to directly create a client on server startup with the specified parameters,
which is useful for automated deployments where you don't have the opportunity
to run separate CLI commands for setup:

```bash
basic-oauth2-server serve \
  --create-default-client \
  --default-client-id my-app \
  --default-client-secret my-secret \
  --default-client-signing-secret my-signing-key \
  --default-client-algorithm HS256
```

### 3. Request a token

#### Client credentials flow
Server to server authentication using the client ID and secret to obtain an access token.

##### Using urlencoded form data:

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=my-app" \
  -d "client_secret=$(echo -n 'my-secret' | base64)"
```

##### Using Basic Auth header:

```bash
curl http://localhost:8080/oauth2/token \
  -u "my-app:$(echo -n 'my-secret' | base64)" \
  -d "grant_type=client_credentials"
```

##### Client credentials flow access token response and structure

```json
{
  "access_token": "ey...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

The access token is a JWT signed via the client_secret you configured the client
with. If you used an asymmetric algorithm, the server must be started with the
corresponding private key, and the public key will be available at the
`.well-known/jwks.json` endpoint for resource servers to verify the token. The
access token of the client credentials flow is the following:

```json
{
  "iss": "$APP_URL",
  "sub": "<client_id>",
  "aud": "<audience requested by client",
  "scope": "read write",
  "azp": "<client_id>",
  "client_id": "<client_id>"
}
```

#### Authorization code flow
User-centric authentication where a user explicitly grants a client application
access to resources on their behalf.  The flow starts with a server creating an
authorization request to the `/authorize` endpoint, which returns a consent page
URL. The user visits the consent page, approves the request, and is redirected
back to the client with an authorization code. The client then exchanges this
code for an access token at the `/oauth2/token` endpoint.

##### 1. Create a user (required for authorization code flow)
You need a user that can "log in" to the authorization server and approve a
client's access request. Create a user with the `users` CLI:

```bash
basic-oauth2-server users create --username alice --password secret
```

##### 2. Create a client with allowed redirect URI
For authorization code flow to work, you have to have a client that has an
approved redirect URI configured. Create a client with the `--redirect-uri`
option:

```bash
basic-oauth2-server clients create \
  --client-id my-app \
  --client-secret my-secret \
  --algorithm HS256 \
  --signing-secret my-signing-key \
  --redirect-uri http://localhost:8080/callback
```

The redirect uri has to be an exact match for the `redirect_uri` parameter used
in the authorization request, otherwise the server will reject the request. You
get the redirect uri from your client, you of course do not know where their
application runs.

##### 3. Start the server

```bash
basic-oauth2-server serve --port 8080 --host localhost
```

**Alternatively**, you can use the *default client* feature to create the client on server startup:

```bash
basic-oauth2-server serve \
  --create-default-client \
  --default-client-id my-app \
  --default-client-secret my-secret \
  --default-client-signing-secret my-signing-key \
  --default-client-algorithm HS256 \
  --default-client-redirect-uris "http://localhost:8080/callback"
```

##### 4. Generate the authorization URL
With the client id, the client can generate an authorization request URL that
the user can visit to approve the client's access request. The URL includes
parameters like `response_type`, `client_id`, `redirect_uri`, `scope`, `state`,
and PKCE parameters if used.

```
http://localhost:8080/authorize
  ?response_type=code
  &client_id=my-app
  &redirect_uri=http://localhost:8080/callback
  &scope=read%20write
  &state=xyz
  &code_challenge=abc123
  &code_challenge_method=S256
```

##### 5. User approves access request and client uses `oauth2/token`
The response of step 4. returns an `/authorize/confirm` URL where the user posts
their consent token to approve the client's access request. If the `POST
/authorize/confirm` is used, it will return a redirect to the requested
`redirect_uri` with the authorization code and state as query parameters. The
client receives tha authorization code and PKCE information that they use to
post to `oauth2/token` endpoint to exchange the code for an access token,
similar to the client credentials flow but with additional parameters:

```
curl -X POST http://localhost:8080/oauth2/token \
  -d "grant_type=authorization_code" \
  -d "client_id=my-app" \
  -d "client_secret=$(echo -n 'my-secret' | base64)" \
  -d "code=the-code-from-query-param" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "code_verifier=the-code-verifier"
```

##### Authorization code flow access token response and structure
The access token response has the same structure as the client credentials flow, but the access token itself contains additional claims about the user and the client:

```{
  "access_token": "ey...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

The access token is a JWT with the following structure:

```json
{
  "iss": "$APP_URL",
  "sub": "<authenticated username>",
  "aud": "<audience requested by client>",
  "scope": "read write",
  "azp": "<client_id>",
  "client_id": "<client_id>"
}
```

## CLI Commands

All functionality is accessed through the `basic-oauth2-server` command:

```
basic-oauth2-server <command> [options]

Commands:
  serve       Start the OAuth authorization server
  clients     Manage OAuth clients (create, list, delete)
  users       Manage users (create, list, delete, update-password)
  admin       Start the admin dashboard server
```

### Shared configuration options

The app shares these configuration options across all commands, which can be set via CLI arguments or environment variables:

| Option      | Environment Variable | Default                 | Description                                                   |
| ----------- | -------------------- | ----------------------- | ------------------------------------------------------------- |
| `--db`      | `OAUTH_DB_PATH`      | `./oauth.db`            | Path to SQLite database file                                  |
| `--app-url` | `APP_URL`            | `http://localhost:8080` | Issuer URL for JWT `iss` claim (should match your server URL) |

### serve

Start the main OAuth authorization server.

```bash
basic-oauth2-server serve [options]
```

| Option                  | Environment Variable        | Default     | Description                       |
| ----------------------- | --------------------------- | ----------- | --------------------------------- |
| `--port`                | `OAUTH_PORT`                | `8080`      | Port for the server               |
| `--host`                | `OAUTH_HOST`                | `localhost` | Host address to bind              |
| `--token-expires-in`    | `OAUTH_TOKEN_EXPIRES_IN`    | `3600`      | Token expiry in seconds           |
| `--rsa-private-key`     | `OAUTH_RSA_PRIVATE_KEY`     | -           | RSA private key for RS*/PS*       |
| `--ec-p256-private-key` | `OAUTH_EC_P256_PRIVATE_KEY` | -           | ECDSA P-256 private key for ES256 |
| `--ec-p384-private-key` | `OAUTH_EC_P384_PRIVATE_KEY` | -           | ECDSA P-384 private key for ES384 |
| `--ec-p521-private-key` | `OAUTH_EC_P521_PRIVATE_KEY` | -           | ECDSA P-521 private key for ES512 |
| `--eddsa-private-key`   | `OAUTH_EDDSA_PRIVATE_KEY`   | -           | Ed25519 private key for EdDSA     |
| `--rsa-key-id`          | `OAUTH_RSA_KEY_ID`          | -           | Key ID for RSA (JWT `kid` header) |
| `--ec-p256-key-id`      | `OAUTH_EC_P256_KEY_ID`      | -           | Key ID for EC P-256               |
| `--ec-p384-key-id`      | `OAUTH_EC_P384_KEY_ID`      | -           | Key ID for EC P-384               |
| `--ec-p521-key-id`      | `OAUTH_EC_P521_KEY_ID`      | -           | Key ID for EC P-521               |
| `--eddsa-key-id`        | `OAUTH_EDDSA_KEY_ID`        | -           | Key ID for EdDSA                  |

**Note:** Private keys are only needed if you have clients using that algorithm. Key IDs are optional and will be included in the JWT header as `kid` when specified. Private key values are treated as file paths by default, or as inline PEM if the value starts with `-----`.

#### Server bootstrapping

The `serve` command can create a default client and/or default user on startup, which is useful for automated deployments:

| Option                            | Default   | Description                                                                     |
| --------------------------------- | --------- | ---------------------------------------------------------------------------     |
| `--create-default-client`         | -         | Create the default OAuth client on startup (skipped if it already exists)       |
| `--default-client-id`             | `default` | Client ID for the default client                                                |
| `--default-client-secret`         | -         | Secret for the default client. Auto-generated and printed if omitted.           |
| `--default-client-algorithm`      | `HS256`   | JWT signing algorithm for the default client                                    |
| `--default-client-signing-secret` | -         | Signing key for the default client. Auto-generated and printed if omitted (HS*) |
| `--default-client-redirect-uris`  | -         | Space-separated redirect URIs for the default client (can be repeated)          |
| `--default-client-scopes`         | -         | Space-separated scopes for the default client (can be repeated)                 |
| `--default-client-audiences`      | -         | Space-separated audiences for the default client (can be repeated)              |
| `--create-default-user`           | -         | Create or update the default user on startup                                    |
| `--default-username`              | `default` | Username for the default user                                                   |
| `--default-password`              | -         | Password for the default user. Prompted securely if omitted.                    |

### clients

Manage OAuth clients via the CLI.

```bash
# Create a new client with HMAC-SHA256 (signing secret auto-generated)
basic-oauth2-server clients create \
  --client-id my-service \
  --client-secret supersecret \
  --algorithm HS256
# Output:
# JWT_ALGORITHM=HS256
# JWT_SECRET=xxxx

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

| Option             | Description                                                                                      |
| ------------------ | ------------------------------------------------------------------------------------------------ |
| `--client-id`      | Client identifier. Auto-generated UUID if omitted.                                               |
| `--title`          | Display name shown on the consent page. Defaults to the client ID.                               |
| `--client-secret`  | Client secret (password for obtaining tokens). Stored as SHA256 hash. Auto-generated if omitted. |
| `--algorithm`      | Signing algorithm: `HS*`, `RS*`, `PS*`, `ES*`, or `EdDSA`                                        |
| `--signing-secret` | Signing secret for HMAC algorithms (auto-generated if not provided for HS256/384/512)            |
| `--scope`          | Add allowed scope. Can be used multiple times.                                                   |
| `--audience`       | Add allowed audience. Can be used multiple times.                                                |
| `--redirect-uri`   | Add allowed redirect URI for authorization code flow. Can be used multiple times.                |

### Secret Formats

The `--client-secret`, `--signing-secret`, and private key options all accept values in these formats:

| Prefix       | Format      | Example                |
| ------------ | ----------- | ---------------------- |
| `@`          | File path   | `@/path/to/secret.txt` |
| `base64:`    | Base64      | `base64:c2VjcmV0...`   |
| `hex:`, `0x` | Hexadecimal | `0xdeadbeef1234...`    |
| (none)       | Plain text  | `my-secret`            |

#### Examples

##### Load client secret and signing secret from files
```bash
# Read secrets from files
basic-oauth2-server clients create \
  --client-id app \
  --client-secret @./client-secret.txt \
  --signing-secret @./signing-key.txt \
  --algorithm HS256
```

##### Load client secret or signing secret from base64-encoded values
```bash
basic-oauth2-server clients create \
  --client-id app \
  --client-secret base64:Y2xpZW50LXNlY3JldA== \
  --signing-secret base64:c2lnbmluZy1rZXk= \
  --algorithm HS256
```

##### Create client with asymmetric signing
This way, there is no per-client signing secret as the private key, that is used
to sign the access tokens, is *private* to the server and never shared.

```bash
basic-oauth2-server clients create \
  --client-id app \
  --client-secret mysecret \
  --algorithm RS256
```

The second step is that the server has to be started with a private key
and optional key id configured:

```bash
basic-oauth2-server serve --rsa-private-key ./private.pem [--rsa-key-id my-rsa-key]
```

All clients share the private key. It is available at `.well-known/jwks.json`
endpoint as a public JWK, so the resource servers can verify the tokens.

### users

Manage users via the CLI. Users are required for the authorization code flow.

```bash
# Create a new user (prompts for password)
basic-oauth2-server users create --username alice

# Create a user with password provided inline (for automation)
basic-oauth2-server users create --username alice --password secret

# List all users
basic-oauth2-server users list

# Update a user's password (prompts for new password)
basic-oauth2-server users update-password --username alice

# Delete a user
basic-oauth2-server users delete --username alice
```

| Option       | Description                                                                          |
| ------------ | ------------------------------------------------------------------------------------ |
| `--username` | The username                                                                         |
| `--password` | The password. Leave empty to be prompted securely. Use only for automation purposes. |

### admin

Start the optional admin dashboard for managing clients via a web UI.

**Note:** Requires the `admin` extra: `pip install basic-oauth2-server[admin]`

```bash
basic-oauth2-server admin [options]
```

| Option   | Environment Variable | Default     | Description                                           |
| -------- | -------------------- | ----------- | ----------------------------------------------------- |
| `--port` | `OAUTH_ADMIN_PORT`   | `8081`      | Port for admin dashboard                              |
| `--host` | `OAUTH_ADMIN_HOST`   | `localhost` | Host address (localhost only by default for security) |

## Token Endpoint

### POST /oauth2/token

Request a new access token. Supports two grant types.

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

#### `client_credentials`

| Parameter       | Required | Description                                                      |
| --------------- | -------- | ---------------------------------------------------------------- |
| `grant_type`    | Yes      | `client_credentials`                                             |
| `client_id`     | Yes      | The client identifier                                            |
| `client_secret` | Yes      | The client secret (the password for the client)                  |
| `scope`         | No       | Space-separated list of requested scopes (i.e. `read write`)     |
| `audience`      | No       | Intended audience for the token (i.e. `https://api.example.com`) |

The parameters `client_id` and `client_secret` can also be provided via HTTP Basic Authentication header instead of the request body.

#### `authorization_code`

| Parameter       | Required | Description                                                  |
| --------------- | -------- | ------------------------------------------------------------ |
| `grant_type`    | Yes      | only `authorization_code`                                    | 
| `client_id`     | Yes      | The client identifier                                        |
| `code`          | Yes      | The authorization code received from `/authorize/confirm`    |
| `redirect_uri`  | Yes      | Must match the `redirect_uri` used in the authorize request  |
| `code_verifier` | Yes      | The PKCE code verifier corresponding to the `code_challenge` |

### JWKS
Audiences can verify access tokens locally via the shared signing secret create
with each client if a symmetric algorithm is used, but if the client uses an
asymmetric algorithm, the audience needs the public key to verify the token. For
this reason there is a JWKS endpoint that exposes the public keys:

```
.well-known/jwks.json
```

It includes all public keys (i.e. `--rsa-private-key`, `--ec-p256-private-key`, etc) configured on the server, with their corresponding key IDs (i.e. `--rsa-key-id`, `--ec-p256-key-id`, etc) if provided, so the resource servers can verify the tokens.

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
| `OAUTH_TOKEN_EXPIRES_IN`    | Token expiry in seconds (default: 3600)              |
| `OAUTH_RSA_PRIVATE_KEY`     | RSA private key for RS*/PS* algorithms               |
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
The `APP_KEY` environment variable is required for encrypting sensitive data
(such as HMAC signing secrets or for signing the consent token in authorization
flow) before storing them in the SQLite database.  Client secrets are stored as
SHA256 hashes and are not affected by the APP_KEY. This key should be a secure,
random string. If no key is provided, a random one will be generated as a
fallback and printed to std out. Either use it, or restart the server and create
a secure one yourself.

Generate a key using openssl:

```bash
openssl rand -base64 32
```

Set it before running any command:

```bash
export APP_KEY="your-generated-key-here"
basic-oauth2-server serve
```

**Important:** Keep this key safe. If you lose it, you will not be able to decrypt existing client secrets in the database.

## Examples

### Setup with HMAC

```bash
# Create a client with HMAC signing
basic-oauth2-server clients create \
  --client-id dev-client \
  --client-secret dev-secret \
  --signing-secret dev-signing-key

# Start the server
basic-oauth2-server serve

# Get a token
curl http://localhost:8080/oauth2/token \
  -d "grant_type=client_credentials" \
  -d "client_id=dev-client" \
  -d "client_secret=$(echo -n 'dev-secret' | base64)"
```

You have to share the client secret with the *resource servers* so that they can
verify the token locally, which is not ideal for production but fine for
development and testing.

### Setup with RSA

```bash
# Generate an RSA private key
openssl genrsa -out private.pem 2048

# Create client with RSA signing
basic-oauth2-server clients create \
  --client-id prod-service \
  --client-secret prod-secret \
  --algorithm RS256 \
  --scope "read,write,admin" \
  --audience "https://api.example.com"

# Start the server with the RSA private key
basic-oauth2-server serve --rsa-private-key private.pem [--rsa-key-id my-rsa-key]
```

**Note:** You have to configure the resource serer to download the public keys from the `.well-known/jwks.json` endpoint to verify the tokens, but you do not have to share any secrets with them.

### Setup with Multiple Algorithm Support
Complex example that shows that you can generate three different types of keys,
create clients that use these keys and one with a shared signing secret, and
start the server with all the private keys configured at the same time, each
with an optional key ID that will be included in the JWT `kid` header for easier
key management on the resource server side.

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
  --rsa-private-key rsa-private.pem \
  --rsa-key-id my-rsa-key-1 \
  --ec-p256-private-key es256-private.pem \
  --ec-p256-key-id my-es256-key-1 \
  --eddsa-private-key ed25519-private.pem \
  --eddsa-key-id my-eddsa-key-1
```

The authorization server will issue different types of tokens depending on the
client's configured algorithm, and the resource servers can verify them by
fetching the keys and using the `kid` header to select the correct key for
verification.

### Running with Admin Dashboard

```bash
# Terminal 1: Start the main server
basic-oauth2-server serve --port 8080

# Terminal 2: Start the admin dashboard
basic-oauth2-server admin --port 8081

# Access the dashboard at http://localhost:8081
```

### Using Environment Variables
Instead of providing everything via CLI arguments, you could also create an .env
file with all the necessary environment variables and load it before starting
the server. For this example, we "inline export" everything:

```bash
export APP_KEY="$(openssl rand -base64 32)"
export APP_URL="https://auth.example.com"
export OAUTH_DB_PATH=/var/lib/oauth2/oauth.db
export OAUTH_PORT=9000

# Set private keys for each algorithm family you want to support
# Note: Environment variables require the `@` prefix to load files. You can remove the `@` and inline the key if you don't care.
export OAUTH_RSA_PRIVATE_KEY="@/etc/oauth2/rsa-private.pem"
export OAUTH_EDDSA_PRIVATE_KEY="@/etc/oauth2/ed25519-private.pem"

# Optionally set key IDs for JWT kid header
export OAUTH_RSA_KEY_ID="rsa-prod-2026"
export OAUTH_EDDSA_KEY_ID="eddsa-prod-2026"

basic-oauth2-server serve
```

## Future Work

- Token revocation endpoint (though that only makes sense when using opaque tokens instead of JWTs)
- Refresh token grant type

## License

MIT
