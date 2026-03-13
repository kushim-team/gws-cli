# Session Validation Removal: Design

## Approach

Remove all server-side session_id validation logic. The bearer token already handles
authentication, and this gateway is stateless — there is no session state to track.
The `Mcp-Session-Id` header is kept for MCP spec compliance only.

## Three-Layer Auth Architecture (Before)

```
session_id → bearer_token → Google OAuth tokens
    ↑              ↑              ↑
  removed      auth factor    actual API access
```

The session_id layer was redundant because bearer_token already authenticates every
request. Removing it simplifies the architecture to:

```
bearer_token → Google OAuth tokens
     ↑              ↑
 auth factor    actual API access
```

## Changes

### `src/mcp_server/http.rs`

1. **AppState**: Remove `sessions: Mutex<HashMap<String, String>>` field
2. **`validate_session()`**: Delete entirely
3. **`handle_post()`**: Remove session validation block and auto-recovery logic.
   On `initialize`, just generate a random session_id for the response header.
4. **`handle_get()`**: Remove session validation block
5. **`handle_delete()`**: Simplify to auth check + `200 OK`
6. **`serve()`**: Remove `sessions` from AppState construction
7. **Tests**: Update/remove tests related to session validation

## Security Considerations

- Bearer token remains the sole authentication factor (no change)
- Session_id value is a random token, not the bearer token, because the MCP
  client's handling of this header is unknown
- No privilege escalation risk — removing an unused validation layer
