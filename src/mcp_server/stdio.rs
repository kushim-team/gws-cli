use super::jsonrpc::{build_jsonrpc_response, build_parse_error_response};
use super::permissions::PermissionContext;
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub(super) async fn serve(config: ServerConfig) -> Result<(), GwsError> {
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    let tools_cache = Mutex::new(None);
    // stdio mode: no permissions (local user has full access).
    let perm_ctx = PermissionContext {
        user_email: None,
        permissions: None,
    };

    while let Ok(Some(line)) = stdin.next_line().await {
        if line.trim().is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => {
                let is_notification = req.get("id").is_none();
                if is_notification {
                    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                    let _ = handle_request(method, &params, &config, &tools_cache, None, &perm_ctx).await;
                    continue;
                }

                let id = req.get("id").unwrap().clone();
                let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let result = handle_request(method, &params, &config, &tools_cache, None, &perm_ctx).await;
                build_jsonrpc_response(&id, result)
            }
            Err(_) => build_parse_error_response(),
        };

        let mut out = match serde_json::to_string(&response) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[gws mcp] Failed to serialize response: {e}");
                continue;
            }
        };
        out.push('\n');
        let _ = stdout.write_all(out.as_bytes()).await;
        let _ = stdout.flush().await;
    }

    Ok(())
}
