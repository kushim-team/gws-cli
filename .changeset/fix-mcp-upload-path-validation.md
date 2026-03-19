---
"@googleworkspace/cli": minor
---

Add inline upload support for remote MCP servers via `upload_content` (base64) and `upload_content_type` parameters. This allows MCP clients to send file data directly without requiring server-side file access. Also harden file-path-based upload validation by reusing `validate_safe_file_path` from validate.rs.
