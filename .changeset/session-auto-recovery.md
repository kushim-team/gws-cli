---
"@googleworkspace/cli": patch
---

Remove server-side session_id validation to eliminate "Session not found or expired" errors after server restarts or idle periods. The bearer token already handles authentication; the Mcp-Session-Id header is kept for spec compliance only.
