//! Permission control for the MCP Gateway (Phase 5 & 6).
//!
//! Loads a YAML configuration that maps users to roles and roles to
//! allowed Discovery method IDs with wildcard support.

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

/// Top-level permissions configuration loaded from YAML.
#[derive(Debug, Deserialize, Clone)]
pub struct PermissionsConfig {
    #[serde(default)]
    pub roles: HashMap<String, RoleDef>,
    #[serde(default)]
    pub users: HashMap<String, UserDef>,
}

/// A role definition containing allowed OAuth scopes and method ID patterns.
///
/// `scopes` is the primary access control layer — it determines which OAuth
/// scopes the role is allowed to use.  At tool-execution time the method's
/// required scopes (from the Discovery Document) are checked against the
/// role's scopes; the request is allowed only when at least one of the
/// method's scopes is present in the role.
///
/// `method` specifies which API method IDs (with optional wildcards) the role
/// is allowed to call.
///
/// Both `scopes` and `method` are always checked.  A request is allowed only
/// when it passes **both** the scope check and the method-pattern check.
/// If either list is empty the corresponding check fails (deny-by-default).
#[derive(Debug, Deserialize, Clone)]
pub struct RoleDef {
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub method: Vec<String>,
}

/// A user definition referencing a role name.
#[derive(Debug, Deserialize, Clone)]
pub struct UserDef {
    pub role: String,
}

impl PermissionsConfig {
    /// Load permissions from a YAML file.
    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read permissions file '{}': {}", path, e))?;
        Self::parse(&content)
    }

    /// Parse permissions from a YAML string.
    pub fn parse(yaml: &str) -> anyhow::Result<Self> {
        let config: PermissionsConfig = serde_yaml::from_str(yaml)
            .map_err(|e| anyhow::anyhow!("Failed to parse permissions YAML: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate that all user role references exist in the roles map.
    fn validate(&self) -> anyhow::Result<()> {
        for (email, user_def) in &self.users {
            if !self.roles.contains_key(&user_def.role) {
                anyhow::bail!(
                    "User '{}' references undefined role '{}'",
                    email,
                    user_def.role
                );
            }
        }
        Ok(())
    }

    /// Get the allowed method patterns for a user.
    /// Returns `None` if the user is not registered (unregistered users get nothing).
    #[cfg(test)]
    pub fn get_allowed_patterns(&self, email: &str) -> Option<&[String]> {
        let user_def = self.users.get(email)?;
        let role_def = self.roles.get(&user_def.role)?;
        Some(&role_def.method)
    }

    /// Get the allowed OAuth scopes for a user.
    /// Returns `None` if the user is not registered.
    #[cfg(test)]
    pub fn get_allowed_scopes(&self, email: &str) -> Option<&[String]> {
        let user_def = self.users.get(email)?;
        let role_def = self.roles.get(&user_def.role)?;
        Some(&role_def.scopes)
    }

    /// Check if a method is allowed for the given user based on both scope
    /// and (optionally) method-pattern checks.
    ///
    /// Convenience wrapper over [`is_method_allowed_with_scopes`] with an
    /// empty method-scope list (scope check is skipped).
    ///
    /// Returns `false` for unregistered users.
    #[cfg(test)]
    pub fn is_method_allowed(&self, email: &str, method_id: &str) -> bool {
        self.is_method_allowed_with_scopes(email, method_id, &[])
    }

    /// Like [`is_method_allowed`] but also checks the method's required
    /// OAuth scopes against the role's allowed scopes.
    pub fn is_method_allowed_with_scopes(
        &self,
        email: &str,
        method_id: &str,
        method_scopes: &[String],
    ) -> bool {
        let user_def = match self.users.get(email) {
            Some(u) => u,
            None => return false,
        };
        let role_def = match self.roles.get(&user_def.role) {
            Some(r) => r,
            None => return false,
        };

        // Scope check: role must have scopes and at least one must match.
        if role_def.scopes.is_empty() {
            return false;
        }
        if !method_scopes.is_empty() {
            let scope_ok = method_scopes
                .iter()
                .any(|ms| role_def.scopes.iter().any(|rs| rs == ms));
            if !scope_ok {
                return false;
            }
        }

        // Method-pattern check: role must have patterns and method must match.
        if role_def.method.is_empty() {
            return false;
        }
        role_def.method.iter().any(|p| matches_pattern(p, method_id))
    }

    /// Return the union of all scopes across every role.
    ///
    /// This is used to compute the minimal OAuth scope set for the gateway's
    /// Google OAuth consent screen when permissions are configured.
    pub fn all_scopes_union(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for role_def in self.roles.values() {
            for scope in &role_def.scopes {
                if seen.insert(scope.clone()) {
                    result.push(scope.clone());
                }
            }
        }
        result
    }

    /// Filter a list of method IDs to only those allowed for the given user.
    /// Returns an empty vec for unregistered users.
    #[cfg(test)]
    pub fn filter_allowed_methods<'a>(
        &self,
        email: &str,
        method_ids: &[&'a str],
    ) -> Vec<&'a str> {
        match self.get_allowed_patterns(email) {
            Some(patterns) => method_ids
                .iter()
                .filter(|mid| patterns.iter().any(|p| matches_pattern(p, mid)))
                .copied()
                .collect(),
            None => vec![],
        }
    }
}

/// Match a wildcard pattern against a method ID.
///
/// Supported patterns:
/// - `"*"` — matches everything
/// - `"gmail.*"` — matches any method starting with `gmail.`
/// - `"gmail.users.messages.*"` — matches any method starting with `gmail.users.messages.`
/// - `"gmail.users.messages.list"` — exact match
pub fn matches_pattern(pattern: &str, method_id: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        // Wildcard: method_id must start with the prefix followed by a dot
        method_id.starts_with(prefix) && method_id[prefix.len()..].starts_with('.')
    } else {
        // Exact match
        pattern == method_id
    }
}

/// Permission context for the current request.
pub(super) struct PermissionContext<'a> {
    /// User email (None in local/stdio mode).
    pub user_email: Option<&'a str>,
    /// Permissions config (None if no permissions file loaded).
    pub permissions: Option<&'a PermissionsConfig>,
}

/// Filter the tools list based on user permissions (scopes + method patterns).
/// Returns all tools if no permissions are configured.
/// Returns empty list for unregistered users when permissions are configured.
///
/// Each tool's JSON value may contain a `_scopes` array (internal metadata,
/// stripped before sending to the client) that lists the OAuth scopes the
/// underlying API method requires.
pub(super) fn filter_tools_by_permissions<'a>(
    tools: &'a [Value],
    perm_ctx: &PermissionContext<'_>,
) -> Vec<&'a Value> {
    let perms = match perm_ctx.permissions {
        Some(p) => p,
        None => return tools.iter().collect(), // No permissions -> all tools
    };

    let email = match perm_ctx.user_email {
        Some(e) => e,
        None => return tools.iter().collect(), // Local mode -> all tools
    };

    let user_def = match perms.users.get(email) {
        Some(u) => u,
        None => return vec![], // Unregistered user -> empty list
    };
    let role_def = match perms.roles.get(&user_def.role) {
        Some(r) => r,
        None => return vec![], // Missing role -> empty list
    };

    // Both scopes and method must be defined on the role.
    if role_def.scopes.is_empty() || role_def.method.is_empty() {
        return vec![];
    }

    tools
        .iter()
        .filter(|tool| {
            let tool_name = tool
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let method_id = tool_name_to_method_id(tool_name);

            // Scope check.
            let method_scopes: Vec<String> = tool
                .get("_scopes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|s| s.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            if !method_scopes.is_empty() {
                let scope_ok = method_scopes
                    .iter()
                    .any(|ms| role_def.scopes.iter().any(|rs| rs == ms));
                if !scope_ok {
                    return false;
                }
            }

            // Method-pattern check.
            role_def.method.iter().any(|p| matches_pattern(p, &method_id))
        })
        .collect()
}

/// Convert a tool name like `drive_files_list` to a method ID like `drive.files.list`.
pub(super) fn tool_name_to_method_id(tool_name: &str) -> String {
    tool_name.replace('_', ".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern_star() {
        assert!(matches_pattern("*", "drive.files.list"));
        assert!(matches_pattern("*", "gmail.users.messages.send"));
    }

    #[test]
    fn test_matches_pattern_service_wildcard() {
        assert!(matches_pattern("gmail.*", "gmail.users.messages.list"));
        assert!(matches_pattern("gmail.*", "gmail.users.labels.list"));
        assert!(!matches_pattern("gmail.*", "drive.files.list"));
        // Must not match the prefix itself without a dot
        assert!(!matches_pattern("gmail.*", "gmail"));
    }

    #[test]
    fn test_matches_pattern_nested_wildcard() {
        assert!(matches_pattern(
            "gmail.users.messages.*",
            "gmail.users.messages.list"
        ));
        assert!(matches_pattern(
            "gmail.users.messages.*",
            "gmail.users.messages.send"
        ));
        assert!(!matches_pattern(
            "gmail.users.messages.*",
            "gmail.users.labels.list"
        ));
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern(
            "gmail.users.messages.list",
            "gmail.users.messages.list"
        ));
        assert!(!matches_pattern(
            "gmail.users.messages.list",
            "gmail.users.messages.send"
        ));
    }

    #[test]
    fn test_parse_valid_yaml() {
        let yaml = r#"
roles:
  admin:
    method:
      - "*"
  reader:
    method:
      - "drive.files.list"
      - "drive.files.get"

users:
  admin@company.com:
    role: admin
  reader@company.com:
    role: reader
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert_eq!(config.roles.len(), 2);
        assert_eq!(config.users.len(), 2);
    }

    #[test]
    fn test_parse_invalid_role_reference() {
        let yaml = r#"
roles:
  admin:
    method:
      - "*"

users:
  user@company.com:
    role: nonexistent
"#;
        let err = PermissionsConfig::parse(yaml).unwrap_err();
        assert!(err.to_string().contains("undefined role"));
    }

    #[test]
    fn test_is_method_allowed_admin() {
        let yaml = r#"
roles:
  admin:
    scopes:
      - "https://www.googleapis.com/auth/drive"
      - "https://www.googleapis.com/auth/gmail.modify"
    method:
      - "*"

users:
  admin@company.com:
    role: admin
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert!(config.is_method_allowed("admin@company.com", "drive.files.list"));
        assert!(config.is_method_allowed("admin@company.com", "gmail.users.messages.send"));
    }

    #[test]
    fn test_is_method_allowed_reader() {
        let yaml = r#"
roles:
  reader:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
    method:
      - "drive.files.list"
      - "drive.files.get"

users:
  reader@company.com:
    role: reader
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert!(config.is_method_allowed("reader@company.com", "drive.files.list"));
        assert!(config.is_method_allowed("reader@company.com", "drive.files.get"));
        assert!(!config.is_method_allowed("reader@company.com", "drive.files.create"));
    }

    #[test]
    fn test_unregistered_user_denied() {
        let yaml = r#"
roles:
  admin:
    scopes:
      - "https://www.googleapis.com/auth/drive"
    method:
      - "*"

users:
  admin@company.com:
    role: admin
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert!(!config.is_method_allowed("unknown@company.com", "drive.files.list"));
    }

    #[test]
    fn test_filter_allowed_methods() {
        let yaml = r#"
roles:
  reader:
    method:
      - "drive.files.*"

users:
  reader@company.com:
    role: reader
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        let methods = vec![
            "drive.files.list",
            "drive.files.get",
            "drive.files.create",
            "gmail.users.messages.list",
        ];
        let allowed = config.filter_allowed_methods("reader@company.com", &methods);
        assert_eq!(
            allowed,
            vec!["drive.files.list", "drive.files.get", "drive.files.create"]
        );
    }

    #[test]
    fn test_filter_allowed_methods_unregistered() {
        let yaml = r#"
roles:
  admin:
    method:
      - "*"

users:
  admin@company.com:
    role: admin
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        let methods = vec!["drive.files.list"];
        let allowed = config.filter_allowed_methods("unknown@company.com", &methods);
        assert!(allowed.is_empty());
    }

    #[test]
    fn test_empty_config() {
        let yaml = r#"
roles: {}
users: {}
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert!(!config.is_method_allowed("anyone@company.com", "drive.files.list"));
    }

    #[test]
    fn test_tool_name_to_method_id() {
        assert_eq!(tool_name_to_method_id("drive_files_list"), "drive.files.list");
        assert_eq!(
            tool_name_to_method_id("gmail_users_messages_send"),
            "gmail.users.messages.send"
        );
        assert_eq!(
            tool_name_to_method_id("calendar_events_get"),
            "calendar.events.get"
        );
    }

    #[test]
    fn test_filter_tools_no_permissions() {
        use serde_json::json;
        let tools = vec![
            json!({"name": "drive_files_list", "description": "List files"}),
            json!({"name": "gmail_users_messages_send", "description": "Send email"}),
        ];
        let perm_ctx = PermissionContext {
            user_email: None,
            permissions: None,
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_tools_unregistered_user() {
        use serde_json::json;
        let tools = vec![
            json!({"name": "drive_files_list", "description": "List files"}),
        ];
        let perms = PermissionsConfig::parse(
            "roles:\n  admin:\n    scopes:\n      - \"https://www.googleapis.com/auth/drive\"\n    method:\n      - \"*\"\nusers:\n  admin@co.com:\n    role: admin\n",
        )
        .unwrap();
        let perm_ctx = PermissionContext {
            user_email: Some("unknown@co.com"),
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_tools_admin_sees_all() {
        use serde_json::json;
        let tools = vec![
            json!({"name": "drive_files_list", "description": "List files"}),
            json!({"name": "gmail_users_messages_send", "description": "Send email"}),
        ];
        let perms = PermissionsConfig::parse(
            "roles:\n  admin:\n    scopes:\n      - \"https://www.googleapis.com/auth/drive\"\n    method:\n      - \"*\"\nusers:\n  admin@co.com:\n    role: admin\n",
        )
        .unwrap();
        let perm_ctx = PermissionContext {
            user_email: Some("admin@co.com"),
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_tools_reader_sees_subset() {
        use serde_json::json;
        let tools = vec![
            json!({"name": "drive_files_list", "description": "List files"}),
            json!({"name": "drive_files_get", "description": "Get file"}),
            json!({"name": "drive_files_create", "description": "Create file"}),
            json!({"name": "gmail_users_messages_send", "description": "Send email"}),
        ];
        let yaml = r#"
roles:
  reader:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
    method:
      - "drive.files.list"
      - "drive.files.get"
users:
  reader@co.com:
    role: reader
"#;
        let perms = PermissionsConfig::parse(yaml).unwrap();
        let perm_ctx = PermissionContext {
            user_email: Some("reader@co.com"),
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0]["name"], "drive_files_list");
        assert_eq!(filtered[1]["name"], "drive_files_get");
    }

    #[test]
    fn test_filter_tools_wildcard_service() {
        use serde_json::json;
        let tools = vec![
            json!({"name": "gmail_users_messages_list", "description": "List"}),
            json!({"name": "gmail_users_messages_send", "description": "Send"}),
            json!({"name": "gmail_users_labels_list", "description": "Labels"}),
            json!({"name": "drive_files_list", "description": "Drive list"}),
        ];
        let yaml = r#"
roles:
  gmail-user:
    scopes:
      - "https://www.googleapis.com/auth/gmail.modify"
    method:
      - "gmail.*"
users:
  user@co.com:
    role: gmail-user
"#;
        let perms = PermissionsConfig::parse(yaml).unwrap();
        let perm_ctx = PermissionContext {
            user_email: Some("user@co.com"),
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_tools_local_mode_no_email() {
        use serde_json::json;
        let tools = vec![
            json!({"name": "drive_files_list", "description": "List files"}),
        ];
        let perms = PermissionsConfig::parse(
            "roles:\n  admin:\n    scopes:\n      - \"https://www.googleapis.com/auth/drive\"\n    method:\n      - \"*\"\nusers:\n  admin@co.com:\n    role: admin\n",
        )
        .unwrap();
        // No user email (local mode) -> all tools visible
        let perm_ctx = PermissionContext {
            user_email: None,
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert_eq!(filtered.len(), 1);
    }

    // ── Scope-based permission tests ──

    #[test]
    fn test_parse_yaml_with_scopes() {
        let yaml = r#"
roles:
  editor:
    scopes:
      - "https://www.googleapis.com/auth/drive"
      - "https://www.googleapis.com/auth/gmail.modify"
    method:
      - "drive.*"
  viewer:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"

users:
  editor@co.com:
    role: editor
  viewer@co.com:
    role: viewer
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert_eq!(config.roles["editor"].scopes.len(), 2);
        assert_eq!(config.roles["viewer"].scopes.len(), 1);
        assert!(config.roles["viewer"].method.is_empty());
    }

    #[test]
    fn test_get_allowed_scopes() {
        let yaml = r#"
roles:
  viewer:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
users:
  viewer@co.com:
    role: viewer
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        let scopes = config.get_allowed_scopes("viewer@co.com").unwrap();
        assert_eq!(scopes, &["https://www.googleapis.com/auth/drive.readonly"]);
        assert!(config.get_allowed_scopes("unknown@co.com").is_none());
    }

    #[test]
    fn test_is_method_allowed_with_scopes_matching() {
        let yaml = r#"
roles:
  editor:
    scopes:
      - "https://www.googleapis.com/auth/drive"
    method:
      - "drive.*"
users:
  user@co.com:
    role: editor
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        // Method requires drive scope — allowed
        assert!(config.is_method_allowed_with_scopes(
            "user@co.com",
            "drive.files.list",
            &["https://www.googleapis.com/auth/drive".to_string(),
              "https://www.googleapis.com/auth/drive.readonly".to_string()],
        ));
    }

    #[test]
    fn test_is_method_allowed_with_scopes_denied() {
        let yaml = r#"
roles:
  viewer:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
    method:
      - "drive.*"
users:
  user@co.com:
    role: viewer
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        // Method requires gmail scope — denied (user only has drive.readonly)
        assert!(!config.is_method_allowed_with_scopes(
            "user@co.com",
            "gmail.users.messages.list",
            &["https://www.googleapis.com/auth/gmail.modify".to_string()],
        ));
    }

    #[test]
    fn test_is_method_allowed_with_scopes_plus_method_pattern() {
        let yaml = r#"
roles:
  restricted:
    scopes:
      - "https://www.googleapis.com/auth/drive"
    method:
      - "drive.files.list"
      - "drive.files.get"
users:
  user@co.com:
    role: restricted
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        let drive_scopes = vec!["https://www.googleapis.com/auth/drive".to_string()];
        // Scope matches AND method matches → allowed
        assert!(config.is_method_allowed_with_scopes(
            "user@co.com", "drive.files.list", &drive_scopes,
        ));
        // Scope matches BUT method doesn't match → denied
        assert!(!config.is_method_allowed_with_scopes(
            "user@co.com", "drive.files.create", &drive_scopes,
        ));
    }

    #[test]
    fn test_empty_scopes_denies_all() {
        let yaml = r#"
roles:
  no-scopes:
    method:
      - "drive.files.*"
users:
  user@co.com:
    role: no-scopes
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        // No scopes defined → always denied
        assert!(!config.is_method_allowed_with_scopes(
            "user@co.com",
            "drive.files.list",
            &["https://www.googleapis.com/auth/drive".to_string()],
        ));
    }

    #[test]
    fn test_empty_method_denies_all() {
        let yaml = r#"
roles:
  no-method:
    scopes:
      - "https://www.googleapis.com/auth/drive"
users:
  user@co.com:
    role: no-method
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        // No method patterns defined → always denied
        assert!(!config.is_method_allowed_with_scopes(
            "user@co.com",
            "drive.files.list",
            &["https://www.googleapis.com/auth/drive".to_string()],
        ));
    }

    #[test]
    fn test_all_scopes_union() {
        let yaml = r#"
roles:
  editor:
    scopes:
      - "https://www.googleapis.com/auth/drive"
      - "https://www.googleapis.com/auth/gmail.modify"
  viewer:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
      - "https://www.googleapis.com/auth/drive"
users:
  e@co.com:
    role: editor
  v@co.com:
    role: viewer
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        let union = config.all_scopes_union();
        // drive appears in both roles but should be deduplicated
        assert!(union.contains(&"https://www.googleapis.com/auth/drive".to_string()));
        assert!(union.contains(&"https://www.googleapis.com/auth/gmail.modify".to_string()));
        assert!(union.contains(&"https://www.googleapis.com/auth/drive.readonly".to_string()));
        assert_eq!(union.len(), 3);
    }

    #[test]
    fn test_all_scopes_union_empty() {
        let yaml = r#"
roles:
  legacy:
    method:
      - "*"
users:
  user@co.com:
    role: legacy
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        assert!(config.all_scopes_union().is_empty());
    }

    #[test]
    fn test_filter_tools_by_scopes_and_method() {
        use serde_json::json;
        let tools = vec![
            json!({
                "name": "drive_files_list",
                "description": "List files",
                "_scopes": ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.readonly"]
            }),
            json!({
                "name": "gmail_users_messages_list",
                "description": "List messages",
                "_scopes": ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.readonly"]
            }),
        ];
        let yaml = r#"
roles:
  drive-only:
    scopes:
      - "https://www.googleapis.com/auth/drive.readonly"
    method:
      - "drive.*"
users:
  user@co.com:
    role: drive-only
"#;
        let perms = PermissionsConfig::parse(yaml).unwrap();
        let perm_ctx = PermissionContext {
            user_email: Some("user@co.com"),
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["name"], "drive_files_list");
    }

    #[test]
    fn test_filter_tools_scopes_plus_method() {
        use serde_json::json;
        let tools = vec![
            json!({
                "name": "drive_files_list",
                "description": "List files",
                "_scopes": ["https://www.googleapis.com/auth/drive"]
            }),
            json!({
                "name": "drive_files_create",
                "description": "Create file",
                "_scopes": ["https://www.googleapis.com/auth/drive"]
            }),
            json!({
                "name": "gmail_users_messages_list",
                "description": "List messages",
                "_scopes": ["https://www.googleapis.com/auth/gmail.modify"]
            }),
        ];
        let yaml = r#"
roles:
  restricted:
    scopes:
      - "https://www.googleapis.com/auth/drive"
    method:
      - "drive.files.list"
users:
  user@co.com:
    role: restricted
"#;
        let perms = PermissionsConfig::parse(yaml).unwrap();
        let perm_ctx = PermissionContext {
            user_email: Some("user@co.com"),
            permissions: Some(&perms),
        };
        let filtered = filter_tools_by_permissions(&tools, &perm_ctx);
        // Only drive_files_list: scope matches AND method matches
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["name"], "drive_files_list");
    }

    #[test]
    fn test_both_scopes_and_method_required() {
        let yaml = r#"
roles:
  scopes-only:
    scopes:
      - "https://www.googleapis.com/auth/drive"
  method-only:
    method:
      - "drive.*"
users:
  s@co.com:
    role: scopes-only
  m@co.com:
    role: method-only
"#;
        let config = PermissionsConfig::parse(yaml).unwrap();
        let drive_scopes = vec!["https://www.googleapis.com/auth/drive".to_string()];
        // scopes-only role: denied because no method patterns
        assert!(!config.is_method_allowed_with_scopes(
            "s@co.com", "drive.files.list", &drive_scopes,
        ));
        // method-only role: denied because no scopes
        assert!(!config.is_method_allowed_with_scopes(
            "m@co.com", "drive.files.list", &drive_scopes,
        ));
    }
}
