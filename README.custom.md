# gws — HODL1 Fork

> This is a fork of [googleworkspace/cli](https://github.com/googleworkspace/cli) maintained by **HODL1** (kushim-team).
> This is **not** an officially supported Google product.

For general usage, installation, and authentication, see the upstream [README.md](README.md).

## Fork Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Kept in sync with upstream `googleworkspace/cli` main. No custom changes. |
| `custom` | All HODL1-specific changes are developed here. |

### Syncing with upstream

```bash
git fetch upstream
git checkout main
git merge upstream/main
git checkout custom
git merge main
```

Upstream updates are merged (not rebased) into `custom` to preserve a clean, shared-friendly history.

### Versioning

The `custom` branch uses `<upstream-version>-hodl1.<N>` versioning (e.g. `0.9.1-hodl1.1`).

- `<upstream-version>` — the upstream release this fork is based on
- `-hodl1.<N>` — HODL1 fork patch number, incremented for each custom release

When syncing with a new upstream version, reset `N` to 1 (e.g. `0.10.0-hodl1.1`). Version is set in both `Cargo.toml` and `package.json`.

## MCP Server

`gws mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io) server over HTTP (Streamable HTTP transport), exposing Google Workspace APIs as structured tools that any MCP-compatible client can call.

```bash
gws mcp -s drive                  # expose Drive tools on port 8080
gws mcp -s drive,gmail,calendar   # expose multiple services
gws mcp -s all                    # expose all services (many tools!)
```

> [!TIP]
> Each service adds roughly 10–80 tools. Keep the list to what you actually need
> to stay under your client's tool limit (typically 50–100 tools).

| Flag                    | Description                                  |
| ----------------------- | -------------------------------------------- |
| `-s, --services <list>`        | Comma-separated services to expose, or `all`           |
| `-w, --workflows`              | Also expose workflow tools                             |
| `-e, --helpers`                | Also expose helper tools                               |
| `-p, --port <port>`            | HTTP port (env: `PORT`, default: 8080)                 |
| `--host <host>`                | Host address to bind (default: 127.0.0.1)              |
| `--permissions-file <path>`    | Path to permissions YAML (env: `GWS_PERMISSIONS_FILE`) |
| `--token-store-backend <mode>` | `memory` (default) or `secret-manager` (env: `GWS_TOKEN_STORE_BACKEND`) |
| `--secret-manager-project <id>`| GCP project ID (env: `GWS_SECRET_MANAGER_PROJECT`)     |
| `--secret-manager-secret <id>` | Secret ID (env: `GWS_SECRET_MANAGER_SECRET`, default: `gws-mcp-sessions`) |

### Permission Control (HTTP Gateway)

When running in HTTP transport mode as a multi-user gateway, you can restrict access per user by providing a YAML permissions file. The permission system uses a **two-layer model** — both layers are always checked:

1. **OAuth scopes** — controls which Google API scopes the role can use.
2. **Method patterns** — controls which specific API methods are allowed.

A request is permitted only when it passes **both** checks. Roles must define both `scopes` and `method`; if either is empty the role denies all access.

```bash
gws mcp -s all \
  --oauth-client-id $CLIENT_ID \
  --gateway-base-url https://gw.example.com \
  --permissions-file config/permissions.yaml
```

Or via environment variable:

```bash
export GWS_PERMISSIONS_FILE=config/permissions.yaml
```

#### YAML format

```yaml
# config/permissions.yaml

roles:
  admin:
    # Primary: which OAuth scopes this role can use
    scopes:
      - "https://www.googleapis.com/auth/drive"
      - "https://www.googleapis.com/auth/gmail.readonly"
      - "https://www.googleapis.com/auth/calendar"
      - "https://www.googleapis.com/auth/spreadsheets"
      - "https://www.googleapis.com/auth/documents"
      - "https://www.googleapis.com/auth/presentations"
      - "https://www.googleapis.com/auth/tasks"
    # Secondary (optional): further restrict to specific methods
    method:
      - "drive.files.list"
      - "drive.files.get"
      - "drive.files.create"
      # ...

  reader:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
      - "https://www.googleapis.com/auth/gmail.readonly"
      - "https://www.googleapis.com/auth/calendar.readonly"
    method:
      - "drive.files.list"
      - "drive.files.get"
      - "gmail.users.messages.list"
      - "calendar.events.list"
      # ...

users:
  admin@company.com:
    role: admin
  reader@company.com:
    role: reader
```

#### How the two layers work

Both `scopes` and `method` are always checked. A request is allowed only when:

1. At least one of the method's required OAuth scopes is present in the role's `scopes`
2. The method ID matches at least one of the role's `method` patterns

If either `scopes` or `method` is empty/missing in the role definition, the role denies all access.

**Example:** A role with `drive.readonly` scope and `method: ["drive.files.list", "drive.files.get"]` can call those two methods (both accept `drive.readonly`) but cannot call `drive.files.create` (not in method list) or `gmail.users.messages.list` (scope mismatch).

#### OAuth scope narrowing

When a permissions file is loaded, the gateway automatically narrows the OAuth consent screen to only request the **union of all role scopes** (plus `openid email profile`). This applies the principle of least privilege — the gateway token only carries scopes that at least one role needs.

You can override this by explicitly setting `--oauth-scopes`:

```bash
# Auto-narrowed from permissions (recommended)
gws mcp -s all --permissions-file config/permissions.yaml ...

# Manual override (ignores permissions scopes)
gws mcp -s all --oauth-scopes "openid email profile https://www.googleapis.com/auth/drive" ...
```

> [!IMPORTANT]
> **Token-level downscoping is not possible** for Google Workspace APIs.
> Google's Credential Access Boundary (CAB) only supports Cloud Storage.
> The gateway enforces scope restrictions at the application layer — the OAuth
> token itself carries the union of all role scopes, but the gateway blocks
> requests to methods outside the user's permitted scopes.

#### Scope reference

Common Google Workspace OAuth scopes:

| Scope | Access level |
|---|---|
| `https://www.googleapis.com/auth/drive` | Full Drive access |
| `https://www.googleapis.com/auth/drive.readonly` | Read-only Drive access |
| `https://www.googleapis.com/auth/gmail.modify` | Read/write Gmail (no send/delete) |
| `https://www.googleapis.com/auth/gmail.readonly` | Read-only Gmail |
| `https://www.googleapis.com/auth/calendar` | Full Calendar access |
| `https://www.googleapis.com/auth/calendar.readonly` | Read-only Calendar |
| `https://www.googleapis.com/auth/spreadsheets` | Full Sheets access |
| `https://www.googleapis.com/auth/spreadsheets.readonly` | Read-only Sheets |
| `https://www.googleapis.com/auth/documents` | Full Docs access |
| `https://www.googleapis.com/auth/documents.readonly` | Read-only Docs |
| `https://www.googleapis.com/auth/presentations` | Full Slides access |
| `https://www.googleapis.com/auth/presentations.readonly` | Read-only Slides |
| `https://www.googleapis.com/auth/tasks` | Full Tasks access |
| `https://www.googleapis.com/auth/tasks.readonly` | Read-only Tasks |

Each API method declares which scopes it accepts in the Discovery Document. For example, `drive.files.list` accepts both `drive` and `drive.readonly`. The method is allowed if the role has **at least one** of the method's accepted scopes.

#### Method patterns

Method IDs follow the naming from Google's Discovery JSON (e.g. `drive.files.list`, `gmail.users.messages.send`). You can inspect available method IDs with `gws schema <method_id>`.

| Pattern                      | Matches                                           |
| ---------------------------- | ------------------------------------------------- |
| `*`                          | All methods across all services                   |
| `gmail.*`                    | All Gmail methods                                 |
| `gmail.users.messages.*`     | All Gmail message methods (list, get, send, etc.) |
| `drive.files.list`           | Exact match only                                  |

#### Behavior

- **HTTP only** — The MCP server uses HTTP transport exclusively. OAuth authentication and permission control are supported.
- **Unregistered users** (email not in `users:`) are denied all access — `tools/list` returns an empty list and `tools/call` returns a permission error.
- **No permissions file** — all authenticated users have full access (backwards-compatible).
- **Missing scopes or method in role** — the role denies all access. Both must be defined.

### Token Store Backend

The gateway supports two backends for persisting OAuth sessions (bearer tokens + Google refresh tokens):

| Backend | Use case | Sessions survive restart? |
|---------|----------|--------------------------|
| `memory` (default) | Local development | No |
| `secret-manager` | Cloud Run production | Yes |

**Local development (in-memory):**

```bash
gws mcp -s drive \
  --oauth-client-id $CLIENT_ID \
  --gateway-base-url http://localhost:8080
# Sessions are lost when the process exits
```

**Cloud Run (Secret Manager):**

```bash
gws mcp -s all \
  --token-store-backend secret-manager \
  --secret-manager-project my-gcp-project \
  --secret-manager-secret gws-mcp-sessions \
  --oauth-client-id $CLIENT_ID \
  --gateway-base-url https://gw.example.com
```

The Secret Manager backend stores all sessions as a single JSON secret. On startup, persisted sessions are loaded into memory. On each session mutation (create, refresh, expire), the secret is updated.

> [!NOTE]
> The Cloud Run service account needs the `Secret Manager Admin` role (`roles/secretmanager.admin`) on the project, or `Secret Manager Secret Version Manager` on the specific secret. The secret is auto-created on first use if it doesn't exist.

## MCP Authorization Specification Compliance

The MCP Gateway's OAuth implementation follows the [MCP Authorization Specification (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization), which is based on:

- [OAuth 2.1 IETF DRAFT](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12)
- [OAuth 2.0 Authorization Server Metadata (RFC 8414)](https://datatracker.ietf.org/doc/html/rfc8414)
- [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://datatracker.ietf.org/doc/html/rfc7591)

Claude Code / Claude Desktop act as MCP clients connecting to this server. Relevant client-side behavior is documented at:

- [Claude Code — Connect to tools via MCP](https://code.claude.com/docs/en/mcp)
- [MCP — Connect to remote MCP Servers](https://modelcontextprotocol.io/docs/develop/connect-remote-servers)

### Key spec requirements affecting this implementation

| Requirement | MCP Spec Level | How this gateway complies |
|---|---|---|
| OAuth 2.1 with PKCE | **MUST** | PKCE S256 enforced, `plain` rejected |
| Authorization Server Metadata (RFC 8414) | **SHOULD** (server) / **MUST** (client) | `/.well-known/oauth-authorization-server` endpoint served; fallback paths also supported |
| Dynamic Client Registration (RFC 7591) | **SHOULD** | `POST /register` implemented (unauthenticated, per RFC 7591) |
| Fallback endpoint paths (`/authorize`, `/token`, `/register`) | **MUST** (if no metadata) | All three default paths are served |
| Redirect URIs: localhost or HTTPS only | **MUST** | `validate_redirect_uri()` enforces this exact rule |
| Bearer token in `Authorization` header | **MUST** | All MCP endpoints require `Authorization: Bearer <token>` |
| HTTP 401 for missing/invalid auth | **MUST** | Implemented with `WWW-Authenticate` header |
| Third-Party Authorization Flow | **MAY** | Gateway acts as OAuth AS (to Claude) + OAuth client (to Google), per spec's "Third-Party Authorization Flow" |

> [!NOTE]
> Some design choices that may appear unusual (e.g., unauthenticated `/register`, accepting any HTTPS URL as `redirect_uri`) are **required by the MCP specification** for interoperability with MCP clients such as Claude Code and Claude Desktop. See [security-analysis/](security-analysis/) for details on how these spec-mandated behaviors affect the threat model.

## AI-DLC Development Cycle

This project (HODL1 fork) follows the [AI-DLC (AI-Driven Development Life Cycle)](https://aws.amazon.com/jp/blogs/devops/ai-driven-development-life-cycle/) methodology.

Intermediate artifacts for each feature are stored in `specs/<feature-name>/`:

```
specs/
  remote-mcp-gateway/
    requirements.md   # Inception: requirements definition
    design.md          # Inception → Construction: design decisions
    tasks.md           # Construction: implementation task breakdown
```

**Workflow:**

1. **Inception** — Organize requirements in `requirements.md` and document design decisions in `design.md`
2. **Construction** — Implement according to the task list in `tasks.md`. AI agents read the specs for context
3. **Operations** — Feed deployment and operational insights back into the specs

When starting a new feature, create a `specs/<feature-name>/` directory with the same 3-file structure.
