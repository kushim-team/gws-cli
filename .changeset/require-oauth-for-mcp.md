---
"@googleworkspace/cli": minor
---

Require OAuth configuration for MCP server startup. The three OAuth parameters (--oauth-client-id, GOOGLE_WORKSPACE_CLI_CLIENT_SECRET, --gateway-base-url) are now mandatory. Local credential fallback via `gws auth login` is removed from the MCP code path.
