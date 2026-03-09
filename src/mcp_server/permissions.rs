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

/// A role definition containing allowed method ID patterns.
#[derive(Debug, Deserialize, Clone)]
pub struct RoleDef {
    #[serde(default)]
    pub allow: Vec<String>,
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
    pub fn get_allowed_patterns(&self, email: &str) -> Option<&[String]> {
        let user_def = self.users.get(email)?;
        let role_def = self.roles.get(&user_def.role)?;
        Some(&role_def.allow)
    }

    /// Check if a specific method ID is allowed for the given user.
    /// Returns `false` for unregistered users.
    pub fn is_method_allowed(&self, email: &str, method_id: &str) -> bool {
        match self.get_allowed_patterns(email) {
            Some(patterns) => patterns.iter().any(|p| matches_pattern(p, method_id)),
            None => false,
        }
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

/// Phase 6: Filter the tools list based on user permissions.
/// Returns all tools if no permissions are configured.
/// Returns empty list for unregistered users when permissions are configured.
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

    let patterns = match perms.get_allowed_patterns(email) {
        Some(p) => p,
        None => return vec![], // Unregistered user -> empty list
    };

    tools
        .iter()
        .filter(|tool| {
            let tool_name = tool
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("");
            let method_id = tool_name_to_method_id(tool_name);
            patterns
                .iter()
                .any(|p| matches_pattern(p, &method_id))
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
    allow:
      - "*"
  reader:
    allow:
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
    allow:
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
    allow:
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
    allow:
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
    allow:
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
    allow:
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
    allow:
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
            "roles:\n  admin:\n    allow:\n      - \"*\"\nusers:\n  admin@co.com:\n    role: admin\n",
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
            "roles:\n  admin:\n    allow:\n      - \"*\"\nusers:\n  admin@co.com:\n    role: admin\n",
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
    allow:
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
    allow:
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
            "roles:\n  admin:\n    allow:\n      - \"*\"\nusers:\n  admin@co.com:\n    role: admin\n",
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
}
