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

mod http;
mod jsonrpc;
pub(crate) mod oauth;
pub(crate) mod permissions;
mod stdio;

use crate::discovery::RestResource;
use crate::error::GwsError;
use crate::services;
use clap::{Arg, Command};
use permissions::{filter_tools_by_permissions, tool_name_to_method_id, PermissionContext};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq)]
enum ToolMode {
    Full,
    Compact,
}

#[derive(Debug, Clone)]
struct ServerConfig {
    services: Vec<String>,
    workflows: bool,
    _helpers: bool,
    tool_mode: ToolMode,
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
                .help("Port for HTTP transport (env: PORT)")
                .env("PORT")
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
        .arg(
            Arg::new("oauth-client-id")
                .long("oauth-client-id")
                .help("Google OAuth client ID for gateway auth (env: GOOGLE_WORKSPACE_CLI_CLIENT_ID)")
                .env("GOOGLE_WORKSPACE_CLI_CLIENT_ID"),
        )
        .arg(
            Arg::new("oauth-client-secret")
                .help("Google OAuth client secret (env only, not accepted as CLI arg)")
                .env("GOOGLE_WORKSPACE_CLI_CLIENT_SECRET")
                .hide(true),
        )
        .arg(
            Arg::new("gateway-base-url")
                .long("gateway-base-url")
                .help("Public base URL of this gateway (env: GWS_GATEWAY_BASE_URL)")
                .env("GWS_GATEWAY_BASE_URL"),
        )
        .arg(
            Arg::new("oauth-scopes")
                .long("oauth-scopes")
                .help("Space-separated OAuth scopes (env: GWS_OAUTH_SCOPES)")
                .env("GWS_OAUTH_SCOPES")
                .default_value(oauth::DEFAULT_OAUTH_SCOPES),
        )
        .arg(
            Arg::new("permissions-file")
                .long("permissions-file")
                .help("Path to permissions YAML file (env: GWS_PERMISSIONS_FILE)")
                .env("GWS_PERMISSIONS_FILE"),
        )
        .arg(
            Arg::new("tool-mode")
                .long("tool-mode")
                .value_parser(["compact", "full"])
                .default_value("full")
                .help("Tool granularity: 'compact' (1 tool/service + discover) or 'full' (1 tool/method)"),
        )
}

fn parse_server_config(matches: &clap::ArgMatches) -> ServerConfig {
    let tool_mode = match matches.get_one::<String>("tool-mode").map(|s| s.as_str()) {
        Some("compact") => ToolMode::Compact,
        _ => ToolMode::Full,
    };
    let mut config = ServerConfig {
        services: Vec::new(),
        workflows: matches.get_flag("workflows"),
        _helpers: matches.get_flag("helpers"),
        tool_mode,
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

/// Initialise the `tracing` subscriber for structured JSON logging to stderr.
///
/// The subscriber outputs Cloud Logging compatible JSON with:
/// - `severity` instead of `level` (Cloud Logging standard field)
/// - Flat structure (no nested `fields` object)
/// - ISO-8601 `timestamp`
///
/// The log level defaults to `info` and can be overridden with the
/// `RUST_LOG` environment variable.
fn init_usage_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt::fmt()
        .event_format(CloudLoggingFormat)
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
}

/// A custom formatter that outputs Cloud Logging compatible JSON.
///
/// Cloud Logging expects `severity` (not `level`) and flat key-value pairs
/// (not nested under `fields`). This formatter produces output like:
/// ```json
/// {"severity":"INFO","timestamp":"2026-03-09T10:30:00.123Z","message":"tool call completed","email":"user@example.com","method_id":"drive_files_list","result":"success"}
/// ```
struct CloudLoggingFormat;

impl<S, N> tracing_subscriber::fmt::FormatEvent<S, N> for CloudLoggingFormat
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> tracing_subscriber::fmt::FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        _ctx: &tracing_subscriber::fmt::FmtContext<'_, S, N>,
        mut writer: tracing_subscriber::fmt::format::Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        use tracing::Level;

        let severity = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARNING",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "DEBUG",
        };

        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true);

        // Collect all fields into a map.
        let mut fields = serde_json::Map::new();
        let mut visitor = JsonFieldVisitor(&mut fields);
        event.record(&mut visitor);

        // Extract `message` from fields (tracing stores it as the first positional arg).
        let message = fields
            .remove("message")
            .and_then(|v| match v {
                serde_json::Value::String(s) => Some(s),
                _ => None,
            })
            .unwrap_or_default();

        // Build the top-level JSON object with flat structure.
        write!(writer, "{{\"severity\":\"{severity}\",\"timestamp\":\"{timestamp}\",\"message\":")?;
        serde_json::to_writer(WriterAdapter(&mut writer), &message)
            .map_err(|_| std::fmt::Error)?;

        for (key, value) in &fields {
            write!(writer, ",\"{key}\":")?;
            serde_json::to_writer(WriterAdapter(&mut writer), value)
                .map_err(|_| std::fmt::Error)?;
        }

        writeln!(writer, "}}")
    }
}

/// Visitor that collects tracing event fields into a `serde_json::Map`.
struct JsonFieldVisitor<'a>(&'a mut serde_json::Map<String, serde_json::Value>);

impl tracing::field::Visit for JsonFieldVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0
            .insert(field.name().to_string(), serde_json::Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            serde_json::Value::String(format!("{:?}", value)),
        );
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }
}

/// Adapter to bridge `std::fmt::Write` (tracing's writer) to `std::io::Write` (serde_json).
struct WriterAdapter<'a, 'b>(&'a mut tracing_subscriber::fmt::format::Writer<'b>);

impl std::io::Write for WriterAdapter<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = std::str::from_utf8(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.0
            .write_str(s)
            .map_err(std::io::Error::other)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub async fn start(args: &[String]) -> Result<(), GwsError> {
    let matches = build_mcp_cli().get_matches_from(args);
    let config = parse_server_config(&matches);

    init_usage_tracing();

    if config.services.is_empty() {
        eprintln!("[gws mcp] Warning: No services configured. Zero tools will be exposed.");
        eprintln!("[gws mcp] Re-run with: gws mcp -s <service> (e.g., -s drive,gmail,calendar)");
        eprintln!("[gws mcp] Use -s all to expose all available services.");
    } else {
        eprintln!(
            "[gws mcp] Starting with services: {}",
            config.services.join(", ")
        );
        eprintln!("[gws mcp] Tool mode: {:?}", config.tool_mode);
    }

    let transport = matches.get_one::<String>("transport").unwrap().as_str();

    // Parse optional OAuth config (all three fields required to enable)
    let oauth_config = match (
        matches.get_one::<String>("oauth-client-id"),
        matches.get_one::<String>("oauth-client-secret"),
        matches.get_one::<String>("gateway-base-url"),
    ) {
        (Some(client_id), Some(client_secret), Some(base_url)) => {
            let base_url = base_url.trim_end_matches('/').to_string();
            oauth::validate_gateway_base_url(&base_url).map_err(|e| {
                GwsError::Validation(e)
            })?;
            let scopes = matches
                .get_one::<String>("oauth-scopes")
                .unwrap()
                .clone();
            eprintln!("[gws mcp] OAuth enabled for gateway auth");
            Some(oauth::OAuthConfig {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                base_url,
                scopes,
            })
        }
        (None, None, None) => None,
        _ => {
            return Err(GwsError::Validation(
                "OAuth requires all three: --oauth-client-id, --oauth-client-secret, --gateway-base-url".to_string(),
            ));
        }
    };

    // Load permissions config if specified.
    let permissions_config = match matches.get_one::<String>("permissions-file") {
        Some(path) => {
            let pc = permissions::PermissionsConfig::load_from_file(path)
                .map_err(GwsError::Other)?;
            eprintln!("[gws mcp] Permissions loaded from {path}");
            Some(pc)
        }
        None => None,
    };

    // When permissions define scopes and the user did not explicitly set
    // --oauth-scopes, narrow the OAuth consent to the union of all role
    // scopes.  This ensures the gateway token only carries the scopes that
    // at least one role needs (principle of least privilege).
    let oauth_config = match (oauth_config, &permissions_config) {
        (Some(mut oc), Some(pc)) => {
            let user_explicitly_set = matches.value_source("oauth-scopes")
                == Some(clap::parser::ValueSource::CommandLine);
            let union = pc.all_scopes_union();
            if !user_explicitly_set && !union.is_empty() {
                let mut scopes = vec!["openid".to_string(), "email".to_string(), "profile".to_string()];
                for s in union {
                    if !scopes.contains(&s) {
                        scopes.push(s);
                    }
                }
                oc.scopes = scopes.join(" ");
                eprintln!("[gws mcp] OAuth scopes narrowed to permissions union: {}", oc.scopes);
            }
            Some(oc)
        }
        (oc, _) => oc,
    };

    match transport {
        "http" => {
            // OAuth and permissions are only supported in HTTP transport mode.
            let port = *matches.get_one::<u16>("port").unwrap();
            let host = matches.get_one::<String>("host").unwrap().clone();
            let allow_origin = matches
                .get_one::<String>("allow-origin")
                .unwrap()
                .clone();
            eprintln!("[gws mcp] Starting HTTP transport on {host}:{port}");
            http::serve(config, &host, port, &allow_origin, oauth_config, permissions_config).await
        }
        _ => {
            // OAuth and permissions are not supported in stdio mode (local user
            // authenticates via local credentials and has full access).
            if oauth_config.is_some() {
                eprintln!("[gws mcp] Warning: OAuth options are ignored in stdio mode. Use -t http for OAuth support.");
            }
            if permissions_config.is_some() {
                eprintln!("[gws mcp] Warning: --permissions-file is ignored in stdio mode. Use -t http for permission control.");
            }
            eprintln!("[gws mcp] Starting stdio transport");
            stdio::serve(config).await
        }
    }
}

// --- Shared request handler ---

/// Handle a JSON-RPC MCP request.
///
/// `access_token` is an optional pre-authenticated Google OAuth access token.
/// When provided (gateway mode), it is used for API calls instead of local credentials.
///
/// `user_email` is the authenticated user's email, used for usage-stats logging.
async fn handle_request(
    method: &str,
    params: &Value,
    config: &ServerConfig,
    tools_cache: &Mutex<Option<Vec<Value>>>,
    access_token: Option<&str>,
    perm_ctx: &PermissionContext<'_>,
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
        "notifications/initialized" => {
            // Do nothing
            Ok(json!({}))
        }
        "tools/list" => {
            let mut cache = tools_cache.lock().await;
            if cache.is_none() {
                *cache = Some(build_tools_list(config).await?);
            }
            let all_tools = cache.as_ref().unwrap();

            // Filter tools by user permissions (scopes + optional allow patterns).
            let filtered = filter_tools_by_permissions(all_tools, perm_ctx);

            // Strip internal `_scopes` metadata before sending to the client.
            let tools: Vec<Value> = filtered
                .into_iter()
                .map(|t| {
                    let mut t = t.clone();
                    if let Some(obj) = t.as_object_mut() {
                        obj.remove("_scopes");
                    }
                    t
                })
                .collect();

            Ok(json!({
                "tools": tools
            }))
        }
        "tools/call" => {
            // MCP spec: tool execution errors should be returned as successful results
            // with isError: true, NOT as JSON-RPC protocol errors. Returning JSON-RPC
            // errors causes clients to show generic "Tool execution failed" with no detail.
            match handle_tools_call(params, config, access_token, perm_ctx).await {
                Ok(val) => Ok(val),
                Err(e) => Ok(json!({
                    "content": [{ "type": "text", "text": e.to_string() }],
                    "isError": true
                })),
            }
        }
        _ => Err(GwsError::Validation(format!(
            "Method not supported: {}",
            method
        ))),
    }
}

// --- Shared tool building logic ---

async fn build_tools_list(config: &ServerConfig) -> Result<Vec<Value>, GwsError> {
    if config.tool_mode == ToolMode::Compact {
        return build_compact_tools_list(config).await;
    }

    let mut tools = Vec::new();

    // 1. Walk core services
    for svc_name in &config.services {
        let (api_name, version) =
            crate::parse_service_and_version(&[svc_name.to_string()], svc_name)?;
        if let Ok(doc) = crate::discovery::fetch_discovery_document(&api_name, &version).await {
            walk_resources(&doc.name, &doc.resources, &mut tools);
        } else {
            eprintln!("[gws mcp] Warning: Failed to load discovery document for service '{}'. It will not be available as a tool.", svc_name);
        }
    }

    // 2. Workflows
    if config.workflows {
        append_workflow_tools(&mut tools);
    }

    Ok(tools)
}

async fn build_compact_tools_list(config: &ServerConfig) -> Result<Vec<Value>, GwsError> {
    let mut tools = Vec::new();

    for svc_name in &config.services {
        let (api_name, version) =
            crate::parse_service_and_version(&[svc_name.to_string()], svc_name)?;

        // Build description with resource names
        let description = if let Ok(doc) =
            crate::discovery::fetch_discovery_document(&api_name, &version).await
        {
            let mut resource_names = Vec::new();
            collect_resource_paths(&doc.resources, "", &mut resource_names);
            resource_names.sort();
            let svc_entry = services::SERVICES
                .iter()
                .find(|e| e.aliases.contains(&svc_name.as_str()));
            let desc = svc_entry.map(|e| e.description).unwrap_or("Google API");
            if resource_names.is_empty() {
                desc.to_string()
            } else {
                let names_str: Vec<&str> = resource_names.iter().map(|s| s.as_str()).collect();
                format!("{}. Resources: {}", desc, names_str.join(", "))
            }
        } else {
            eprintln!(
                "[gws mcp] Warning: Failed to load discovery document for '{}'. Tool will have minimal description.",
                svc_name
            );
            format!("Google Workspace API: {}", svc_name)
        };

        tools.push(json!({
            "name": svc_name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "resource": {
                        "type": "string",
                        "description": "Resource name (e.g., files, permissions)"
                    },
                    "method": {
                        "type": "string",
                        "description": "Method name (e.g., list, get, create)"
                    },
                    "params": {
                        "type": "object",
                        "description": "Query or path parameters"
                    },
                    "body": {
                        "type": "object",
                        "description": "Request body"
                    },
                    "upload": {
                        "type": "string",
                        "description": "Local file path to upload"
                    },
                    "page_all": {
                        "type": "boolean",
                        "description": "Auto-paginate, returning all pages"
                    }
                },
                "required": ["resource", "method"]
            }
        }));
    }

    // Add gws_discover meta-tool
    tools.push(json!({
        "name": "gws_discover",
        "description": "Query available resources, methods, and parameter schemas for any enabled service. Call with service only to list resources; add resource to list methods; add method to get full parameter schema.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {
                    "type": "string",
                    "description": "Service name (e.g., drive, gmail)"
                },
                "resource": {
                    "type": "string",
                    "description": "Resource name to list methods for"
                },
                "method": {
                    "type": "string",
                    "description": "Method name to get full parameter schema"
                }
            },
            "required": ["service"]
        }
    }));

    // Workflows (same as full mode)
    if config.workflows {
        append_workflow_tools(&mut tools);
    }

    Ok(tools)
}

fn append_workflow_tools(tools: &mut Vec<Value>) {
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

fn walk_resources(prefix: &str, resources: &HashMap<String, RestResource>, tools: &mut Vec<Value>) {
    for (res_name, res) in resources {
        let new_prefix = format!("{}_{}", prefix, res_name);

        for (method_name, method) in &res.methods {
            let tool_name = format!("{}_{}", new_prefix, method_name);
            let mut description = method.description.clone().unwrap_or_default();
            if description.is_empty() {
                description = format!("Execute the {} Google API method", tool_name);
            }

            // Generate JSON Schema for MCP input — only include body/upload
            // when the Discovery Document method actually supports them.
            let mut properties = serde_json::Map::new();
            properties.insert(
                "params".to_string(),
                json!({
                    "type": "object",
                    "description": "Query or path parameters (e.g. fileId, q, pageSize)"
                }),
            );
            if method.request.is_some() {
                properties.insert(
                    "body".to_string(),
                    json!({
                        "type": "object",
                        "description": "Request body API object"
                    }),
                );
            }
            if method.supports_media_upload {
                properties.insert(
                    "upload".to_string(),
                    json!({
                        "type": "string",
                        "description": "Local file path to upload as media content"
                    }),
                );
            }
            if method.parameters.contains_key("pageToken") {
                properties.insert(
                    "page_all".to_string(),
                    json!({
                        "type": "boolean",
                        "description": "Auto-paginate, returning all pages"
                    }),
                );
            }
            let input_schema = json!({
                "type": "object",
                "properties": properties
            });

            let mut tool = json!({
                "name": tool_name,
                "description": description,
                "inputSchema": input_schema
            });

            // Attach method scopes as internal metadata for permission filtering.
            // This field is stripped before sending to the client.
            if !method.scopes.is_empty() {
                tool["_scopes"] = json!(method.scopes);
            }

            tools.push(tool);
        }

        // Recurse into sub-resources
        if !res.resources.is_empty() {
            walk_resources(&new_prefix, &res.resources, tools);
        }
    }
}

async fn handle_discover(arguments: &Value, config: &ServerConfig) -> Result<Value, GwsError> {
    let service = arguments
        .get("service")
        .and_then(|v| v.as_str())
        .ok_or_else(|| GwsError::Validation("Missing 'service' in gws_discover".to_string()))?;

    if !config.services.contains(&service.to_string()) {
        return Err(GwsError::Validation(format!(
            "Service '{}' is not enabled. Enabled: {}",
            service,
            config.services.join(", ")
        )));
    }

    let (api_name, version) = crate::parse_service_and_version(&[service.to_string()], service)?;
    let doc = crate::discovery::fetch_discovery_document(&api_name, &version).await?;

    let resource_name = arguments.get("resource").and_then(|v| v.as_str());
    let method_name = arguments.get("method").and_then(|v| v.as_str());

    let result = match (resource_name, method_name) {
        // Level 1: list all resources (recursively, with dot-separated paths)
        (None, _) => {
            let mut resource_entries = Vec::new();
            collect_resource_entries(&doc.resources, "", &mut resource_entries);
            json!({ "service": service, "resources": resource_entries })
        }
        // Level 2: list methods and sub-resources for a resource
        (Some(res), None) => {
            let mut all_paths = Vec::new();
            collect_resource_paths(&doc.resources, "", &mut all_paths);
            let resource = find_resource(&doc.resources, res).ok_or_else(|| {
                GwsError::Validation(format!(
                    "Resource '{}' not found in {}. Available: {}",
                    res,
                    service,
                    all_paths.join(", ")
                ))
            })?;
            let methods: Vec<Value> = resource
                .methods
                .iter()
                .map(|(name, m)| {
                    json!({
                        "name": name,
                        "httpMethod": m.http_method,
                        "description": m.description.as_deref().unwrap_or("")
                    })
                })
                .collect();
            let sub_resources: Vec<&str> = resource.resources.keys().map(|s| s.as_str()).collect();
            let mut result = json!({ "service": service, "resource": res, "methods": methods });
            if !sub_resources.is_empty() {
                result["subResources"] = json!(sub_resources);
            }
            result
        }
        // Level 3: full param schema for a method
        (Some(res), Some(meth)) => {
            let resource = find_resource(&doc.resources, res).ok_or_else(|| {
                let mut all_paths = Vec::new();
                collect_resource_paths(&doc.resources, "", &mut all_paths);
                GwsError::Validation(format!(
                    "Resource '{}' not found in {}. Available: {}",
                    res,
                    service,
                    all_paths.join(", ")
                ))
            })?;
            let method = resource.methods.get(meth).ok_or_else(|| {
                GwsError::Validation(format!(
                    "Method '{}' not found in {}.{}. Available: {}",
                    meth,
                    service,
                    res,
                    resource
                        .methods
                        .keys()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
            let params: Vec<Value> = method
                .parameters
                .iter()
                .map(|(name, p)| {
                    json!({
                        "name": name,
                        "type": p.param_type.as_deref().unwrap_or("string"),
                        "required": p.required,
                        "location": p.location.as_deref().unwrap_or("query"),
                        "description": p.description.as_deref().unwrap_or("")
                    })
                })
                .collect();
            json!({
                "service": service,
                "resource": res,
                "method": meth,
                "httpMethod": method.http_method,
                "description": method.description.as_deref().unwrap_or(""),
                "parameters": params,
                "supportsMediaUpload": method.supports_media_upload,
                "supportsMediaDownload": method.supports_media_download
            })
        }
    };

    Ok(json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_default() }],
        "isError": false
    }))
}

/// Recursively collect all resource paths (dot-separated) from a resource tree.
fn collect_resource_paths(
    resources: &HashMap<String, RestResource>,
    prefix: &str,
    out: &mut Vec<String>,
) {
    for (name, res) in resources {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", prefix, name)
        };
        out.push(path.clone());
        if !res.resources.is_empty() {
            collect_resource_paths(&res.resources, &path, out);
        }
    }
}

/// Recursively collect resource entries (name + methods) for discover Level 1.
fn collect_resource_entries(
    resources: &HashMap<String, RestResource>,
    prefix: &str,
    out: &mut Vec<Value>,
) {
    for (name, res) in resources {
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", prefix, name)
        };
        let methods: Vec<&str> = res.methods.keys().map(|s| s.as_str()).collect();
        if !methods.is_empty() {
            out.push(json!({
                "name": path.clone(),
                "methods": methods
            }));
        }
        if !res.resources.is_empty() {
            collect_resource_entries(&res.resources, &path, out);
        }
    }
}

/// Walk into potentially nested resources by dot-separated path (e.g., "projects.locations.templates").
fn find_resource<'a>(
    resources: &'a HashMap<String, RestResource>,
    path: &str,
) -> Option<&'a RestResource> {
    let mut segments = path.split('.');
    let first_segment = segments.next()?;
    let mut current_res = resources.get(first_segment)?;
    for segment in segments {
        current_res = current_res.resources.get(segment)?;
    }
    Some(current_res)
}

async fn handle_tools_call(
    params: &Value,
    config: &ServerConfig,
    access_token: Option<&str>,
    perm_ctx: &PermissionContext<'_>,
) -> Result<Value, GwsError> {
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

    if tool_name == "gws_discover" {
        return handle_discover(arguments, config).await;
    }

    // Compact mode: tool_name IS the service alias, resource/method are in arguments
    if config.tool_mode == ToolMode::Compact {
        let resource_path = arguments
            .get("resource")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GwsError::Validation("Missing 'resource' argument".to_string()))?;
        let method_name = arguments
            .get("method")
            .and_then(|v| v.as_str())
            .ok_or_else(|| GwsError::Validation("Missing 'method' argument".to_string()))?;

        let svc_alias = tool_name;
        if !config.services.contains(&svc_alias.to_string()) {
            return Err(GwsError::Validation(format!(
                "Service '{}' is not enabled in this MCP session",
                svc_alias
            )));
        }

        let (api_name, version) =
            crate::parse_service_and_version(&[svc_alias.to_string()], svc_alias)?;
        let doc = crate::discovery::fetch_discovery_document(&api_name, &version).await?;

        let resource = find_resource(&doc.resources, resource_path).ok_or_else(|| {
            GwsError::Validation(format!(
                "Resource '{}' not found in {}",
                resource_path, svc_alias
            ))
        })?;

        let method = resource.methods.get(method_name).ok_or_else(|| {
            GwsError::Validation(format!(
                "Method '{}' not found in {}.{}",
                method_name, svc_alias, resource_path
            ))
        })?;

        return execute_mcp_method(&doc, method, arguments, access_token, perm_ctx, tool_name).await;
    }

    // Full mode: tool_name encodes service_resource_method (e.g., drive_files_list)
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

    // Walk: ["drive", "files", "list"] — iterate resource path segments between service and method
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

    // Check permissions (scopes + optional allow patterns) before executing.
    if let Some(perms) = perm_ctx.permissions {
        if let Some(email) = perm_ctx.user_email {
            let method_id = tool_name_to_method_id(tool_name);
            if !perms.is_method_allowed_with_scopes(email, &method_id, &method.scopes) {
                return Err(GwsError::Validation(format!(
                    "Permission denied: '{}' is not allowed for user '{}'",
                    method_id, email
                )));
            }
        }
    }

    execute_mcp_method(&doc, method, arguments, access_token, perm_ctx, tool_name).await
}

async fn execute_mcp_method(
    doc: &crate::discovery::RestDescription,
    method: &crate::discovery::RestMethod,
    arguments: &Value,
    access_token: Option<&str>,
    perm_ctx: &PermissionContext<'_>,
    tool_name: &str,
) -> Result<Value, GwsError> {
    let params_json_val = arguments.get("params");
    let params_str = params_json_val
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| GwsError::Validation(format!("Failed to serialize params: {e}")))?;

    // Drop empty body objects — LLMs commonly send "body": {} even on GET
    // methods, which causes Google APIs to return 400.
    let body_json_val = arguments
        .get("body")
        .filter(|v| !v.as_object().is_some_and(|m| m.is_empty()));
    let body_str = body_json_val
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| GwsError::Validation(format!("Failed to serialize body: {e}")))?;

    let upload_path = if let Some(raw) = arguments
        .get("upload")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
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

    let scopes: Vec<&str> = crate::select_scope(&method.scopes).into_iter().collect();
    let (token, auth_method) = if let Some(tok) = access_token {
        // Gateway mode: use the pre-authenticated user's Google token.
        (Some(tok.to_string()), crate::executor::AuthMethod::OAuth)
    } else {
        // Local mode: use local credentials.
        match crate::auth::get_token(&scopes).await {
            Ok(t) => (Some(t), crate::executor::AuthMethod::OAuth),
            Err(e) => {
                eprintln!(
                    "[gws mcp] Warning: Authentication failed, proceeding without credentials: {e}"
                );
                (None, crate::executor::AuthMethod::None)
            }
        }
    };

    let result = crate::executor::execute_method(
        doc,
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
    .await;

    let email = perm_ctx.user_email.unwrap_or("anonymous");

    match &result {
        Ok(_) => {
            tracing::info!(
                email = email,
                method_id = tool_name,
                result = "success",
                "tool call completed"
            );
        }
        Err(e) => {
            tracing::warn!(
                email = email,
                method_id = tool_name,
                result = "error",
                error = %e,
                "tool call failed"
            );
        }
    }

    let result = result?;

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

#[cfg(test)]
mod usage_stats_tests {
    use super::*;
    use tokio::sync::Mutex;

    fn no_perms_ctx(email: Option<&str>) -> PermissionContext<'_> {
        PermissionContext {
            user_email: email,
            permissions: None,
        }
    }

    #[tokio::test]
    async fn test_handle_request_initialize_with_email() {
        let tools_cache = Mutex::new(None);
        let config = ServerConfig {
            services: vec![],
            workflows: false,
            _helpers: false,
            tool_mode: ToolMode::Full,
        };
        let perm_ctx = no_perms_ctx(Some("user@example.com"));
        let result = handle_request(
            "initialize",
            &json!({}),
            &config,
            &tools_cache,
            None,
            &perm_ctx,
        )
        .await;
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["serverInfo"]["name"], "gws-mcp");
    }

    #[tokio::test]
    async fn test_handle_request_initialize_without_email() {
        let tools_cache = Mutex::new(None);
        let config = ServerConfig {
            services: vec![],
            workflows: false,
            _helpers: false,
            tool_mode: ToolMode::Full,
        };
        let perm_ctx = no_perms_ctx(None);
        let result = handle_request(
            "initialize",
            &json!({}),
            &config,
            &tools_cache,
            None,
            &perm_ctx,
        )
        .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_request_tools_call_invalid_name_logs_error() {
        let tools_cache = Mutex::new(None);
        let config = ServerConfig {
            services: vec!["drive".to_string()],
            workflows: false,
            _helpers: false,
            tool_mode: ToolMode::Full,
        };
        let perm_ctx = no_perms_ctx(Some("alice@test.com"));
        // Missing 'name' should return validation error
        let result = handle_request(
            "tools/call",
            &json!({}),
            &config,
            &tools_cache,
            None,
            &perm_ctx,
        )
        .await;
        // tools/call errors are now wrapped as isError:true
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val["isError"], true);
    }

    #[tokio::test]
    async fn test_handle_request_unsupported_method() {
        let tools_cache = Mutex::new(None);
        let config = ServerConfig {
            services: vec![],
            workflows: false,
            _helpers: false,
            tool_mode: ToolMode::Full,
        };
        let perm_ctx = no_perms_ctx(Some("user@test.com"));
        let result = handle_request(
            "unsupported/method",
            &json!({}),
            &config,
            &tools_cache,
            None,
            &perm_ctx,
        )
        .await;
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{MethodParameter, RestDescription, RestMethod, RestResource};
    use std::collections::HashMap;

    fn mock_config_compact(services: Vec<&str>) -> ServerConfig {
        ServerConfig {
            services: services.into_iter().map(String::from).collect(),
            workflows: false,
            _helpers: false,
            tool_mode: ToolMode::Compact,
        }
    }

    fn mock_doc() -> RestDescription {
        let mut params = HashMap::new();
        params.insert(
            "fileId".to_string(),
            MethodParameter {
                param_type: Some("string".to_string()),
                required: true,
                location: Some("path".to_string()),
                description: Some("The ID of the file".to_string()),
                ..Default::default()
            },
        );
        params.insert(
            "fields".to_string(),
            MethodParameter {
                param_type: Some("string".to_string()),
                required: false,
                location: Some("query".to_string()),
                description: Some("Selector specifying fields".to_string()),
                ..Default::default()
            },
        );

        let mut methods = HashMap::new();
        methods.insert(
            "list".to_string(),
            RestMethod {
                http_method: "GET".to_string(),
                path: "files".to_string(),
                description: Some("Lists files".to_string()),
                ..Default::default()
            },
        );
        methods.insert(
            "get".to_string(),
            RestMethod {
                http_method: "GET".to_string(),
                path: "files/{fileId}".to_string(),
                description: Some("Gets a file".to_string()),
                parameters: params,
                ..Default::default()
            },
        );

        let mut resources = HashMap::new();
        resources.insert(
            "files".to_string(),
            RestResource {
                methods,
                ..Default::default()
            },
        );

        RestDescription {
            name: "drive".to_string(),
            resources,
            ..Default::default()
        }
    }

    /// Mock a nested doc like Gmail: users -> messages, threads
    fn mock_nested_doc() -> RestDescription {
        let mut msg_methods = HashMap::new();
        msg_methods.insert(
            "list".to_string(),
            RestMethod {
                http_method: "GET".to_string(),
                path: "messages".to_string(),
                description: Some("Lists messages".to_string()),
                ..Default::default()
            },
        );
        msg_methods.insert(
            "get".to_string(),
            RestMethod {
                http_method: "GET".to_string(),
                path: "messages/{id}".to_string(),
                description: Some("Gets a message".to_string()),
                ..Default::default()
            },
        );
        let messages = RestResource {
            methods: msg_methods,
            ..Default::default()
        };

        let mut thread_methods = HashMap::new();
        thread_methods.insert(
            "list".to_string(),
            RestMethod {
                http_method: "GET".to_string(),
                path: "threads".to_string(),
                ..Default::default()
            },
        );
        let threads = RestResource {
            methods: thread_methods,
            ..Default::default()
        };

        let mut user_methods = HashMap::new();
        user_methods.insert(
            "getProfile".to_string(),
            RestMethod {
                http_method: "GET".to_string(),
                path: "users/{userId}/profile".to_string(),
                ..Default::default()
            },
        );

        let mut sub_resources = HashMap::new();
        sub_resources.insert("messages".to_string(), messages);
        sub_resources.insert("threads".to_string(), threads);

        let users = RestResource {
            methods: user_methods,
            resources: sub_resources,
        };

        let mut resources = HashMap::new();
        resources.insert("users".to_string(), users);

        RestDescription {
            name: "gmail".to_string(),
            resources,
            ..Default::default()
        }
    }

    // -- find_resource tests --

    #[test]
    fn test_find_resource_top_level() {
        let doc = mock_doc();
        let res = find_resource(&doc.resources, "files");
        assert!(res.is_some());
        assert!(res.unwrap().methods.contains_key("list"));
    }

    #[test]
    fn test_find_resource_not_found() {
        let doc = mock_doc();
        assert!(find_resource(&doc.resources, "missing").is_none());
    }

    #[test]
    fn test_find_resource_nested_dot_path() {
        let mut inner_methods = HashMap::new();
        inner_methods.insert(
            "create".to_string(),
            RestMethod {
                http_method: "POST".to_string(),
                path: "permissions".to_string(),
                ..Default::default()
            },
        );
        let inner = RestResource {
            methods: inner_methods,
            ..Default::default()
        };
        let mut sub_resources = HashMap::new();
        sub_resources.insert("permissions".to_string(), inner);

        let outer = RestResource {
            resources: sub_resources,
            ..Default::default()
        };
        let mut top = HashMap::new();
        top.insert("files".to_string(), outer);

        let res = find_resource(&top, "files.permissions");
        assert!(res.is_some());
        assert!(res.unwrap().methods.contains_key("create"));
    }

    // -- collect_resource_paths tests --

    #[test]
    fn test_collect_resource_paths_flat() {
        let doc = mock_doc();
        let mut paths = Vec::new();
        collect_resource_paths(&doc.resources, "", &mut paths);
        paths.sort();
        assert_eq!(paths, vec!["files"]);
    }

    #[test]
    fn test_collect_resource_paths_nested() {
        let doc = mock_nested_doc();
        let mut paths = Vec::new();
        collect_resource_paths(&doc.resources, "", &mut paths);
        paths.sort();
        assert!(paths.contains(&"users".to_string()));
        assert!(paths.contains(&"users.messages".to_string()));
    }

    // -- collect_resource_entries tests --

    #[test]
    fn test_collect_resource_entries_includes_nested() {
        let doc = mock_nested_doc();
        let mut entries = Vec::new();
        collect_resource_entries(&doc.resources, "", &mut entries);
        let names: Vec<&str> = entries.iter().filter_map(|e| e["name"].as_str()).collect();
        assert!(names.contains(&"users"));
        assert!(names.contains(&"users.messages"));
    }

    // -- handle_discover tests --

    #[tokio::test]
    async fn test_discover_service_not_enabled() {
        let config = mock_config_compact(vec!["gmail"]);
        let args = json!({"service": "drive"});

        let result = handle_discover(&args, &config).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not enabled"));
    }

    #[tokio::test]
    async fn test_discover_missing_service_arg() {
        let config = mock_config_compact(vec!["drive"]);
        let args = json!({});

        let result = handle_discover(&args, &config).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Missing 'service'"));
    }

    // -- ToolMode tests --

    #[test]
    fn test_tool_mode_enum_equality() {
        assert_eq!(ToolMode::Compact, ToolMode::Compact);
        assert_ne!(ToolMode::Compact, ToolMode::Full);
    }

    // -- CLI parsing tests --

    #[test]
    fn test_cli_tool_mode_default_is_full() {
        let cli = build_mcp_cli();
        let matches = cli.get_matches_from(vec!["mcp"]);
        let mode = matches.get_one::<String>("tool-mode").unwrap();
        assert_eq!(mode, "full");
    }

    #[test]
    fn test_cli_tool_mode_compact() {
        let cli = build_mcp_cli();
        let matches = cli.get_matches_from(vec!["mcp", "--tool-mode", "compact"]);
        let mode = matches.get_one::<String>("tool-mode").unwrap();
        assert_eq!(mode, "compact");
    }

    #[test]
    fn test_cli_tool_mode_invalid_rejected() {
        let cli = build_mcp_cli();
        let result = cli.try_get_matches_from(vec!["mcp", "--tool-mode", "invalid"]);
        assert!(result.is_err());
    }

    // -- append_workflow_tools tests --

    #[test]
    fn test_append_workflow_tools_adds_five() {
        let mut tools = Vec::new();
        append_workflow_tools(&mut tools);
        assert_eq!(tools.len(), 5);
        assert_eq!(tools[0]["name"], "workflow_standup_report");
        assert_eq!(tools[4]["name"], "workflow_file_announce");
    }
}
