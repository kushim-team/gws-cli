// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Model Context Protocol (MCP) server implementation.
//! Provides both stdio and Streamable HTTP transports exposing Google Workspace APIs as MCP tools.

use crate::discovery::RestResource;
use crate::error::GwsError;
use crate::services;
use clap::{Arg, Command};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub(crate) struct ServerConfig {
    pub services: Vec<String>,
    pub workflows: bool,
    pub _helpers: bool,
}

fn build_mcp_cli() -> Command {
    Command::new("mcp")
        .about("Starts the MCP server (stdio or HTTP)")
        .arg(
            Arg::new("services")
                .long("services")
                .short('s')
                .help("Comma separated list of services to expose (e.g., drive,gmail,all)")
                .default_value(""),
        )
        .arg(
            Arg::new("workflows")
                .long("workflows")
                .short('w')
                .action(clap::ArgAction::SetTrue)
                .help("Expose workflows as tools"),
        )
        .arg(
            Arg::new("helpers")
                .long("helpers")
                .short('e')
                .action(clap::ArgAction::SetTrue)
                .help("Expose service-specific helpers as tools"),
        )
        .arg(
            Arg::new("transport")
                .long("transport")
                .short('t')
                .help("Transport mode: stdio or http")
                .default_value("stdio")
                .value_parser(["stdio", "http"]),
        )
        .arg(
            Arg::new("port")
                .long("port")
                .short('p')
                .help("Port for HTTP transport")
                .default_value("8080")
                .value_parser(clap::value_parser!(u16)),
        )
        .arg(
            Arg::new("host")
                .long("host")
                .help("Host address to bind for HTTP transport (use 0.0.0.0 for all interfaces)")
                .default_value("127.0.0.1"),
        )
        .arg(
            Arg::new("allow-origin")
                .long("allow-origin")
                .help("Allowed Origin header values (comma-separated). If unset, localhost origins are allowed by default.")
                .default_value(""),
        )
}

fn parse_server_config(matches: &clap::ArgMatches) -> ServerConfig {
    let mut config = ServerConfig {
        services: Vec::new(),
        workflows: matches.get_flag("workflows"),
        _helpers: matches.get_flag("helpers"),
    };

    let svc_str = matches.get_one::<String>("services").unwrap();
    if !svc_str.is_empty() {
        if svc_str == "all" {
            config.services = services::SERVICES
                .iter()
                .map(|s| s.aliases[0].to_string())
                .collect();
        } else {
            config.services = svc_str.split(',').map(|s| s.trim().to_string()).collect();
        }
    }

    config
}

pub async fn start(args: &[String]) -> Result<(), GwsError> {
    let matches = build_mcp_cli().get_matches_from(args);
    let config = parse_server_config(&matches);

    if config.services.is_empty() {
        eprintln!("[gws mcp] Warning: No services configured. Zero tools will be exposed.");
        eprintln!("[gws mcp] Re-run with: gws mcp -s <service> (e.g., -s drive,gmail,calendar)");
        eprintln!("[gws mcp] Use -s all to expose all available services.");
    } else {
        eprintln!(
            "[gws mcp] Starting with services: {}",
            config.services.join(", ")
        );
    }

    let transport = matches.get_one::<String>("transport").unwrap().as_str();

    match transport {
        "http" => {
            let port = *matches.get_one::<u16>("port").unwrap();
            let host = matches.get_one::<String>("host").unwrap().clone();
            let allow_origin = matches
                .get_one::<String>("allow-origin")
                .unwrap()
                .clone();
            eprintln!("[gws mcp] Starting HTTP transport on {host}:{port}");
            http_transport::serve(config, &host, port, &allow_origin).await
        }
        _ => {
            eprintln!("[gws mcp] Starting stdio transport");
            stdio_transport::serve(config).await
        }
    }
}

// --- Shared request handler ---

pub(crate) async fn handle_request(
    method: &str,
    params: &Value,
    config: &ServerConfig,
    tools_cache: &Mutex<Option<Vec<Value>>>,
) -> Result<Value, GwsError> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "gws-mcp",
                "version": env!("CARGO_PKG_VERSION")
            },
            "capabilities": {
                "tools": {}
            }
        })),
        "notifications/initialized" => Ok(json!({})),
        "tools/list" => {
            let mut cache = tools_cache.lock().await;
            if cache.is_none() {
                *cache = Some(build_tools_list(config).await?);
            }
            Ok(json!({
                "tools": cache.as_ref().unwrap()
            }))
        }
        "tools/call" => handle_tools_call(params, config).await,
        _ => Err(GwsError::Validation(format!(
            "Method not supported: {}",
            method
        ))),
    }
}

pub(crate) fn build_jsonrpc_response(id: &Value, result: Result<Value, GwsError>) -> Value {
    match result {
        Ok(res) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": res
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32603,
                "message": e.to_string()
            }
        }),
    }
}

pub(crate) fn build_parse_error_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": {
            "code": -32700,
            "message": "Parse error"
        }
    })
}

// --- stdio transport ---

mod stdio_transport {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    pub async fn serve(config: ServerConfig) -> Result<(), GwsError> {
        let mut stdin = BufReader::new(tokio::io::stdin()).lines();
        let mut stdout = tokio::io::stdout();
        let tools_cache = Mutex::new(None);

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
                        let _ = handle_request(method, &params, &config, &tools_cache).await;
                        continue;
                    }

                    let id = req.get("id").unwrap().clone();
                    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
                    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                    let result = handle_request(method, &params, &config, &tools_cache).await;
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
}

// --- HTTP (Streamable HTTP) transport ---

mod http_transport {
    use super::*;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{delete, get, post};
    use axum::Router;
    use std::collections::HashSet;

    struct AppState {
        config: ServerConfig,
        tools_cache: Mutex<Option<Vec<Value>>>,
        sessions: Mutex<HashSet<String>>,
        allowed_origins: Vec<String>,
    }

    pub async fn serve(
        config: ServerConfig,
        host: &str,
        port: u16,
        allow_origin: &str,
    ) -> Result<(), GwsError> {
        let allowed_origins: Vec<String> = if allow_origin.is_empty() {
            vec![]
        } else {
            allow_origin
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        };

        let state = Arc::new(AppState {
            config,
            tools_cache: Mutex::new(None),
            sessions: Mutex::new(HashSet::new()),
            allowed_origins,
        });

        let app = Router::new()
            .route("/mcp", post(handle_post))
            .route("/mcp", get(handle_get))
            .route("/mcp", delete(handle_delete))
            .with_state(state);

        let addr: std::net::SocketAddr = format!("{host}:{port}")
            .parse()
            .map_err(|e| GwsError::Other(anyhow::anyhow!("Invalid host address: {e}")))?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| GwsError::Other(anyhow::anyhow!("Failed to bind to {addr}: {e}")))?;

        eprintln!("[gws mcp] HTTP server listening on http://{addr}/mcp");

        axum::serve(listener, app)
            .await
            .map_err(|e| GwsError::Other(anyhow::anyhow!("HTTP server error: {e}")))?;

        Ok(())
    }

    fn get_session_id(headers: &HeaderMap) -> Option<String> {
        headers
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    /// Validate Origin header to prevent DNS rebinding attacks.
    /// Returns true if the request is allowed.
    /// If no Origin header is present (non-browser client), the request is allowed.
    fn validate_origin(headers: &HeaderMap, allowed_origins: &[String]) -> bool {
        let origin = match headers.get("origin").and_then(|v| v.to_str().ok()) {
            Some(o) => o,
            None => return true,
        };

        if !allowed_origins.is_empty() {
            return allowed_origins.iter().any(|a| a == origin);
        }

        // Default: allow localhost origins only
        let lower = origin.to_lowercase();
        lower.starts_with("http://localhost")
            || lower.starts_with("https://localhost")
            || lower.starts_with("http://127.0.0.1")
            || lower.starts_with("https://127.0.0.1")
            || lower.starts_with("http://[::1]")
            || lower.starts_with("https://[::1]")
    }

    /// Validate session ID. Returns Ok(session_id) or an error Response.
    /// Missing header → 400 Bad Request, unknown/expired session → 404 Not Found.
    async fn validate_session(
        headers: &HeaderMap,
        sessions: &Mutex<HashSet<String>>,
    ) -> Result<String, Response> {
        match get_session_id(headers) {
            Some(id) => {
                let sessions = sessions.lock().await;
                if sessions.contains(&id) {
                    Ok(id)
                } else {
                    Err((
                        StatusCode::NOT_FOUND,
                        "Session not found or expired",
                    )
                        .into_response())
                }
            }
            None => Err((
                StatusCode::BAD_REQUEST,
                "Missing Mcp-Session-Id header",
            )
                .into_response()),
        }
    }

    /// POST /mcp - Handle JSON-RPC requests (single or batch)
    async fn handle_post(
        State(state): State<Arc<AppState>>,
        headers: HeaderMap,
        body: String,
    ) -> Response {
        // 1. Origin validation
        if !validate_origin(&headers, &state.allowed_origins) {
            return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
        }

        // 2. Accept header must include both application/json and text/event-stream
        if let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) {
            let has_json = accept.contains("application/json") || accept.contains("*/*");
            let has_sse = accept.contains("text/event-stream") || accept.contains("*/*");
            if !has_json || !has_sse {
                return (
                    StatusCode::NOT_ACCEPTABLE,
                    "Accept header must include both application/json and text/event-stream",
                )
                    .into_response();
            }
        }

        // 3. Parse body — single object or JSON-RPC batch array
        let parsed: Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => {
                let error_resp = build_parse_error_response();
                return (
                    StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    )],
                    serde_json::to_string(&error_resp).unwrap(),
                )
                    .into_response();
            }
        };

        let (messages, is_batch) = if let Some(arr) = parsed.as_array() {
            (arr.clone(), true)
        } else {
            (vec![parsed], false)
        };

        if messages.is_empty() {
            let error_resp = json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": { "code": -32600, "message": "Invalid Request: empty batch" }
            });
            return (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                serde_json::to_string(&error_resp).unwrap(),
            )
                .into_response();
        }

        // Check if any message is an initialize request
        let has_initialize = messages
            .iter()
            .any(|m| m.get("method").and_then(|v| v.as_str()) == Some("initialize"));

        // Session validation for non-initialize requests
        if !has_initialize {
            if let Err(resp) = validate_session(&headers, &state.sessions).await {
                return resp;
            }
        }

        // 4. Process each message
        let mut responses = Vec::new();
        let mut new_session_id: Option<String> = None;

        for msg in &messages {
            let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
            let has_id = msg.get("id").is_some();
            let has_method = msg.get("method").is_some();

            // Notification (no id) or client response (id but no method) → process, no response
            if !has_id || !has_method {
                if has_method {
                    let _ =
                        handle_request(method, &params, &state.config, &state.tools_cache).await;
                }
                continue;
            }

            // JSON-RPC request (has both id and method)
            let id = msg.get("id").unwrap().clone();
            let result = handle_request(method, &params, &state.config, &state.tools_cache).await;
            let response = build_jsonrpc_response(&id, result);

            if method == "initialize" {
                let session_id = uuid::Uuid::new_v4().to_string();
                state.sessions.lock().await.insert(session_id.clone());
                new_session_id = Some(session_id);
            }

            responses.push(response);
        }

        // 5. If all messages were notifications/responses, return 202 Accepted
        if responses.is_empty() {
            return StatusCode::ACCEPTED.into_response();
        }

        // 6. Build HTTP response
        let mut resp_headers = HeaderMap::new();
        if let Some(ref sid) = new_session_id {
            resp_headers.insert("mcp-session-id", HeaderValue::from_str(sid).unwrap());
        } else if let Some(sid) = get_session_id(&headers) {
            resp_headers.insert("mcp-session-id", HeaderValue::from_str(&sid).unwrap());
        }
        resp_headers.insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let body_str = if is_batch {
            serde_json::to_string(&responses).unwrap()
        } else {
            serde_json::to_string(&responses[0]).unwrap()
        };

        (StatusCode::OK, resp_headers, body_str).into_response()
    }

    /// GET /mcp - SSE endpoint for server-to-client notifications
    async fn handle_get(
        State(state): State<Arc<AppState>>,
        headers: HeaderMap,
    ) -> Response {
        // Origin validation
        if !validate_origin(&headers, &state.allowed_origins) {
            return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
        }

        // Accept header must include text/event-stream
        if let Some(accept) = headers.get("accept").and_then(|v| v.to_str().ok()) {
            if !accept.contains("text/event-stream") && !accept.contains("*/*") {
                return (
                    StatusCode::NOT_ACCEPTABLE,
                    "Accept header must include text/event-stream",
                )
                    .into_response();
            }
        }

        // Session validation (404 for unknown, 400 for missing)
        if let Err(resp) = validate_session(&headers, &state.sessions).await {
            return resp;
        }

        // Return an SSE stream that stays open.
        // For now, we just keep the connection open (no server-initiated notifications yet).
        let stream = futures_util::stream::pending::<Result<String, std::convert::Infallible>>();
        let body = Body::from_stream(stream);

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/event-stream")
            .header("cache-control", "no-cache")
            .body(body)
            .unwrap()
    }

    /// DELETE /mcp - Terminate session
    async fn handle_delete(
        State(state): State<Arc<AppState>>,
        headers: HeaderMap,
    ) -> Response {
        // Origin validation
        if !validate_origin(&headers, &state.allowed_origins) {
            return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
        }

        let session_id = get_session_id(&headers);
        match session_id {
            Some(ref id) => {
                let mut sessions = state.sessions.lock().await;
                if sessions.remove(id) {
                    StatusCode::OK.into_response()
                } else {
                    (StatusCode::NOT_FOUND, "Session not found").into_response()
                }
            }
            None => (
                StatusCode::BAD_REQUEST,
                "Missing Mcp-Session-Id header",
            )
                .into_response(),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use axum::body::to_bytes;
        use axum::http::Request;
        use tower::ServiceExt;

        const ACCEPT_MCP: &str = "application/json, text/event-stream";

        fn test_state() -> Arc<AppState> {
            test_state_with_origins(vec![])
        }

        fn test_state_with_origins(allowed_origins: Vec<String>) -> Arc<AppState> {
            Arc::new(AppState {
                config: ServerConfig {
                    services: vec![],
                    workflows: false,
                    _helpers: false,
                },
                tools_cache: Mutex::new(None),
                sessions: Mutex::new(HashSet::new()),
                allowed_origins,
            })
        }

        fn test_app(state: Arc<AppState>) -> Router {
            Router::new()
                .route("/mcp", post(handle_post))
                .route("/mcp", get(handle_get))
                .route("/mcp", delete(handle_delete))
                .with_state(state)
        }

        /// Helper: send an initialize request and return the session ID.
        async fn init_session(app: &Router) -> String {
            let init_body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            });
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .body(Body::from(serde_json::to_string(&init_body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            resp.headers()
                .get("mcp-session-id")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        }

        #[tokio::test]
        async fn test_initialize_returns_session_id() {
            let state = test_state();
            let app = test_app(state.clone());

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert!(resp.headers().get("mcp-session-id").is_some());

            let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            let result: Value = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(result["result"]["protocolVersion"], "2024-11-05");
            assert_eq!(result["result"]["serverInfo"]["name"], "gws-mcp");
        }

        #[tokio::test]
        async fn test_tools_list_requires_session() {
            let state = test_state();
            let app = test_app(state);

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            // No session header → 400 Bad Request
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_tools_list_with_valid_session() {
            let state = test_state();
            let app = test_app(state.clone());
            let session_id = init_session(&app).await;

            let list_body = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&list_body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            let result: Value = serde_json::from_slice(&body_bytes).unwrap();
            assert!(result["result"]["tools"].is_array());
        }

        #[tokio::test]
        async fn test_delete_session() {
            let state = test_state();
            let app = test_app(state.clone());
            let session_id = init_session(&app).await;

            // Delete session
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/mcp")
                        .header("mcp-session-id", &session_id)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);

            // Verify session is gone — terminated session returns 404
            let list_body = json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&list_body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_notification_returns_accepted() {
            let state = test_state();
            let app = test_app(state.clone());
            let session_id = init_session(&app).await;

            // Send notification (no "id" field) → 202 Accepted
            let notif_body = json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&notif_body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::ACCEPTED);
        }

        #[tokio::test]
        async fn test_parse_error() {
            let state = test_state();
            let app = test_app(state);

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .body(Body::from("not valid json"))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            let result: Value = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(result["error"]["code"], -32700);
        }

        #[tokio::test]
        async fn test_delete_without_session_header() {
            let state = test_state();
            let app = test_app(state);

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/mcp")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        #[tokio::test]
        async fn test_delete_unknown_session() {
            let state = test_state();
            let app = test_app(state);

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("DELETE")
                        .uri("/mcp")
                        .header("mcp-session-id", "nonexistent-session")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        // --- New tests for MCP spec compliance ---

        #[tokio::test]
        async fn test_invalid_session_returns_not_found() {
            let state = test_state();
            let app = test_app(state);

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            });

            // Present but invalid session ID → 404 Not Found
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", "does-not-exist")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }

        #[tokio::test]
        async fn test_batch_request() {
            let state = test_state();
            let app = test_app(state.clone());
            let session_id = init_session(&app).await;

            let batch = json!([
                {
                    "jsonrpc": "2.0",
                    "id": 10,
                    "method": "tools/list",
                    "params": {}
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {}
                }
            ]);

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&batch).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            let body_bytes = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
            let result: Value = serde_json::from_slice(&body_bytes).unwrap();
            // Batch response is an array
            assert!(result.is_array());
            let arr = result.as_array().unwrap();
            // Only 1 response (notification doesn't get a response)
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["id"], 10);
        }

        #[tokio::test]
        async fn test_batch_all_notifications_returns_accepted() {
            let state = test_state();
            let app = test_app(state.clone());
            let session_id = init_session(&app).await;

            let batch = json!([
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {}
                }
            ]);

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("mcp-session-id", &session_id)
                        .body(Body::from(serde_json::to_string(&batch).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::ACCEPTED);
        }

        #[tokio::test]
        async fn test_origin_validation_rejects_bad_origin() {
            let state = test_state();
            let app = test_app(state);

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("origin", "https://evil.example.com")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        #[tokio::test]
        async fn test_origin_validation_allows_localhost() {
            let state = test_state();
            let app = test_app(state);

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("origin", "http://localhost:3000")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_origin_validation_allows_configured_origin() {
            let state =
                test_state_with_origins(vec!["https://my-app.example.com".to_string()]);
            let app = test_app(state);

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            });

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", ACCEPT_MCP)
                        .header("origin", "https://my-app.example.com")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
        }

        #[tokio::test]
        async fn test_accept_header_missing_event_stream() {
            let state = test_state();
            let app = test_app(state);

            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            });

            // Only application/json without text/event-stream → 406
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/mcp")
                        .header("content-type", "application/json")
                        .header("accept", "application/json")
                        .body(Body::from(serde_json::to_string(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
        }

        #[tokio::test]
        async fn test_get_requires_accept_event_stream() {
            let state = test_state();
            let app = test_app(state.clone());
            let session_id = init_session(&app).await;

            // GET with wrong Accept → 406
            let resp = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/mcp")
                        .header("accept", "application/json")
                        .header("mcp-session-id", &session_id)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::NOT_ACCEPTABLE);
        }

        #[tokio::test]
        async fn test_get_invalid_session_returns_not_found() {
            let state = test_state();
            let app = test_app(state);

            let resp = app
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/mcp")
                        .header("accept", "text/event-stream")
                        .header("mcp-session-id", "does-not-exist")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        }
    }
}

// --- Shared tool building logic ---

async fn build_tools_list(config: &ServerConfig) -> Result<Vec<Value>, GwsError> {
    let mut tools = Vec::new();

    for svc_name in &config.services {
        let (api_name, version) =
            crate::parse_service_and_version(std::slice::from_ref(svc_name), svc_name)?;
        if let Ok(doc) = crate::discovery::fetch_discovery_document(&api_name, &version).await {
            walk_resources(&doc.name, &doc.resources, &mut tools);
        } else {
            eprintln!("[gws mcp] Warning: Failed to load discovery document for service '{}'. It will not be available as a tool.", svc_name);
        }
    }

    if config.workflows {
        tools.push(json!({
            "name": "workflow_standup_report",
            "description": "Today's meetings + open tasks as a standup summary",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "format": { "type": "string", "description": "Output format: json, table, yaml, csv" }
                }
            }
        }));
        tools.push(json!({
            "name": "workflow_meeting_prep",
            "description": "Prepare for your next meeting: agenda, attendees, and linked docs",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "calendar": { "type": "string", "description": "Calendar ID (default: primary)" }
                }
            }
        }));
        tools.push(json!({
            "name": "workflow_email_to_task",
            "description": "Convert a Gmail message into a Google Tasks entry",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "message_id": { "type": "string", "description": "Gmail message ID" },
                    "tasklist": { "type": "string", "description": "Task list ID" }
                },
                "required": ["message_id"]
            }
        }));
        tools.push(json!({
            "name": "workflow_weekly_digest",
            "description": "Weekly summary: this week's meetings + unread email count",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "format": { "type": "string", "description": "Output format" }
                }
            }
        }));
        tools.push(json!({
            "name": "workflow_file_announce",
            "description": "Announce a Drive file in a Chat space",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_id": { "type": "string", "description": "Drive file ID" },
                    "space": { "type": "string", "description": "Chat space name" },
                    "message": { "type": "string", "description": "Custom message" }
                },
                "required": ["file_id", "space"]
            }
        }));
    }

    Ok(tools)
}

fn walk_resources(prefix: &str, resources: &HashMap<String, RestResource>, tools: &mut Vec<Value>) {
    for (res_name, res) in resources {
        let new_prefix = format!("{}_{}", prefix, res_name);

        for (method_name, method) in &res.methods {
            let tool_name = format!("{}_{}", new_prefix, method_name);
            let mut description = method.description.clone().unwrap_or_default();
            if description.is_empty() {
                description = format!("Execute the {} Google API method", tool_name);
            }

            let input_schema = json!({
                "type": "object",
                "properties": {
                    "params": {
                        "type": "object",
                        "description": "Query or path parameters (e.g. fileId, q, pageSize)"
                    },
                    "body": {
                        "type": "object",
                        "description": "Request body API object"
                    },
                    "upload": {
                        "type": "string",
                        "description": "Local file path to upload as media content"
                    },
                    "page_all": {
                        "type": "boolean",
                        "description": "Auto-paginate, returning all pages"
                    }
                }
            });

            tools.push(json!({
                "name": tool_name,
                "description": description,
                "inputSchema": input_schema
            }));
        }

        if !res.resources.is_empty() {
            walk_resources(&new_prefix, &res.resources, tools);
        }
    }
}

async fn handle_tools_call(params: &Value, config: &ServerConfig) -> Result<Value, GwsError> {
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| GwsError::Validation("Missing 'name' in tools/call".to_string()))?;

    let default_args = json!({});
    let arguments = params.get("arguments").unwrap_or(&default_args);

    if tool_name.starts_with("workflow_") {
        return Err(GwsError::Other(anyhow::anyhow!(
            "Workflows are not yet fully implemented via MCP"
        )));
    }

    let parts: Vec<&str> = tool_name.split('_').collect();
    if parts.len() < 3 {
        return Err(GwsError::Validation(format!(
            "Invalid API tool name: {}",
            tool_name
        )));
    }

    let svc_alias = parts[0];

    if !config.services.contains(&svc_alias.to_string()) {
        return Err(GwsError::Validation(format!(
            "Service '{}' is not enabled in this MCP session",
            svc_alias
        )));
    }

    let (api_name, version) =
        crate::parse_service_and_version(&[svc_alias.to_string()], svc_alias)?;
    let doc = crate::discovery::fetch_discovery_document(&api_name, &version).await?;

    let mut current_resources = &doc.resources;
    let mut current_res = None;

    for res_name in &parts[1..parts.len() - 1] {
        if let Some(res) = current_resources.get(*res_name) {
            current_res = Some(res);
            current_resources = &res.resources;
        } else {
            return Err(GwsError::Validation(format!(
                "Resource '{}' not found in Discovery Document",
                res_name
            )));
        }
    }

    let method_name = parts.last().unwrap();
    let method = if let Some(res) = current_res {
        res.methods
            .get(*method_name)
            .ok_or_else(|| GwsError::Validation(format!("Method '{}' not found", method_name)))?
    } else {
        return Err(GwsError::Validation("Resource not found".to_string()));
    };

    let params_json_val = arguments.get("params");
    let params_str = params_json_val
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| GwsError::Validation(format!("Failed to serialize params: {e}")))?;

    let body_json_val = arguments.get("body");
    let body_str = body_json_val
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| GwsError::Validation(format!("Failed to serialize body: {e}")))?;

    // Security: validate upload path to prevent arbitrary local file reads.
    let upload_path = if let Some(raw) = arguments.get("upload").and_then(|v| v.as_str()) {
        let p = std::path::Path::new(raw);
        if p.is_absolute() || p.components().any(|c| c == std::path::Component::ParentDir) {
            return Err(GwsError::Validation(format!(
                "Upload path '{}' is not allowed. Paths must be relative and within the current directory.",
                raw
            )));
        }
        Some(raw)
    } else {
        None
    };
    let page_all = arguments
        .get("page_all")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let pagination = crate::executor::PaginationConfig {
        page_all,
        page_limit: 100,
        page_delay_ms: 100,
    };

    let scopes: Vec<&str> = method.scopes.iter().map(|s| s.as_str()).collect();
    let (token, auth_method) = match crate::auth::get_token(&scopes, None).await {
        Ok(t) => (Some(t), crate::executor::AuthMethod::OAuth),
        Err(e) => {
            eprintln!(
                "[gws mcp] Warning: Authentication failed, proceeding without credentials: {e}"
            );
            (None, crate::executor::AuthMethod::None)
        }
    };

    let result = crate::executor::execute_method(
        &doc,
        method,
        params_str.as_deref(),
        body_str.as_deref(),
        token.as_deref(),
        auth_method,
        None,
        upload_path,
        false,
        &pagination,
        None,
        &crate::helpers::modelarmor::SanitizeMode::Warn,
        &crate::formatter::OutputFormat::default(),
        true,
    )
    .await?;

    let text_content = match result {
        Some(val) => serde_json::to_string_pretty(&val).unwrap_or_else(|_| "[]".to_string()),
        None => "Execution completed with no output.".to_string(),
    };

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text_content
            }
        ],
        "isError": false
    }))
}
