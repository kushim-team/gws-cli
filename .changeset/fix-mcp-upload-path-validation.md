---
"@googleworkspace/cli": minor
---

Add `POST /upload` endpoint and `upload_ref` parameter for MCP file uploads. Clients upload files via HTTP to `/upload` (up to 50 MiB), receive an `upload_id`, then pass it as `upload_ref` in media-upload tool calls (e.g. `drive_files_create`). This replaces the previous file-path-based `upload` parameter which was unusable for remote MCP servers.
