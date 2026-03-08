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

//! Permission control for the MCP Gateway (Phase 5 & 6).
//!
//! Loads a YAML configuration that maps users to roles and roles to
//! allowed Discovery method IDs with wildcard support.

use serde::Deserialize;
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
}
