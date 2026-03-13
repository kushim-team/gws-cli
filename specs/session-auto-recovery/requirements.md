# Session Validation Removal: Requirements

## Problem

When a Streamable HTTP MCP session becomes invalid (server restart, Cloud Run cold start,
or session eviction), all subsequent requests fail with `404 Session not found or expired`.
There is no automatic recovery mechanism — users must manually restart the MCP server or
reconnect via `/mcp`, which may also fail.

## Root Cause

`AppState.sessions` (session_id → bearer_token mapping) is purely in-memory and never
persisted. When the server restarts, this mapping is lost even though `bearer_sessions`
(bearer_token → UserSession) can survive via Secret Manager persistence.

## Analysis

Through design discussion, we determined that server-side session_id validation is
unnecessary for this gateway because:

1. **Stateless gateway**: This server is a stateless proxy — it holds no session state
   beyond authentication. There is nothing to "bind" to a session_id.
2. **Bearer token is the sole auth factor**: Authentication is fully handled by the
   bearer token, which is validated on every request via `resolve_google_token()`.
   The session_id adds no additional security.
3. **MCP spec compliance**: The `Mcp-Session-Id` header is required by the MCP
   specification, but the spec does not mandate server-side validation beyond using
   it as a correlation identifier.

## Requirements

1. **Remove server-side session tracking**: Delete the `sessions` HashMap from
   `AppState` and the `validate_session()` function entirely.

2. **Keep spec compliance**: Continue returning `Mcp-Session-Id` in responses to
   the `initialize` request. Generate a random token (not the bearer token) as the
   session_id value, since the MCP client's handling of this value is unknown and
   sensitive data should not be exposed.

3. **Simplify DELETE**: `DELETE /mcp` should only require valid authentication
   (bearer token). It returns `200 OK` regardless of session_id presence or value.

4. **No auth changes**: Bearer token validation remains unchanged on all endpoints.

## Non-Requirements

- Persisting session state (there is no session state to persist).
- Client-side changes (Claude Code MCP client).
- Token revocation on DELETE (RFC 7009 is optional and not implemented).
