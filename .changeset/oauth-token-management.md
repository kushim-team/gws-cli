---
"@googleworkspace/cli": minor
---

Add OAuth token management for MCP Gateway (Phase 2)

- Add per-user Google OAuth token storage and management
- Implement OAuth 2.1 Authorization Code + PKCE flow endpoints:
  `/.well-known/oauth-authorization-server`, `/authorize`, `/oauth/callback`, `/token`, `/register`
- Add authentication middleware for HTTP transport (Bearer token validation)
- Support automatic Google token refresh when expired
- Gateway mode uses per-user Google tokens; local (stdio) mode unchanged
- New CLI flags: `--oauth-client-id`, `--oauth-client-secret`, `--gateway-base-url`, `--oauth-scopes`
