use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use thiserror::Error;

pub const ANY: &str = "any";
pub const MAX_ATOM_LEN: usize = 64;
pub const MAX_RULES: usize = 64;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read policy: {0}")]
    Read(#[from] std::io::Error),
    #[error("invalid policy yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid atom `{value}` at byte {index}: 0x{byte:02x}")]
    InvalidAtom {
        value: String,
        index: usize,
        byte: u8,
    },
    #[error("atom `{value}` is empty")]
    EmptyAtom { value: String },
    #[error("atom `{value}` is longer than {limit} bytes")]
    AtomTooLong { value: String, limit: usize },
    #[error("duplicate rule name `{name}`")]
    DuplicateRuleName { name: String },
    #[error("duplicate principal id `{id}`")]
    DuplicatePrincipalId { id: String },
    #[error("duplicate resource id `{id}`")]
    DuplicateResourceId { id: String },
    #[error("rule `{rule}` is missing selector `{selector}`")]
    MissingSelector {
        rule: String,
        selector: &'static str,
    },
    #[error("rule `{rule}` references unknown principal `{principal}`")]
    UnknownPrincipal { rule: String, principal: String },
    #[error("rule `{rule}` references unknown resource `{resource}`")]
    UnknownResource { rule: String, resource: String },
    #[error("invalid duration `{0}`")]
    InvalidDuration(String),
    #[error("rule `{rule}` max_ttl exceeds CA max_ttl")]
    TtlExceedsCaMax { rule: String },
    #[error("too many rules: {actual}; limit is {limit}")]
    TooManyRules { actual: usize, limit: usize },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version: u32,
    pub ca: CaConfig,
    pub principals: Vec<PrincipalConfig>,
    pub resources: Vec<ResourceConfig>,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaConfig {
    pub name: String,
    pub default_ttl: String,
    pub max_ttl: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalConfig {
    pub id: String,
    pub ssh_principals: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    pub id: String,
    pub host: String,
    pub trusted_ca_path: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    pub effect: Effect,
    pub principal: Option<String>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub ssh_principal: Option<String>,
    pub max_ttl: Option<String>,
}

impl PolicyFile {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let text = fs::read_to_string(path)?;
        Self::from_yaml_str(&text)
    }

    pub fn from_yaml_str(text: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_yaml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn ca_default_ttl_seconds(&self) -> Result<u64, PolicyError> {
        parse_duration_seconds(&self.ca.default_ttl)
    }

    pub fn ca_max_ttl_seconds(&self) -> Result<u64, PolicyError> {
        parse_duration_seconds(&self.ca.max_ttl)
    }

    pub fn principal(&self, id: &str) -> Option<&PrincipalConfig> {
        self.principals.iter().find(|principal| principal.id == id)
    }

    pub fn resource(&self, id: &str) -> Option<&ResourceConfig> {
        self.resources.iter().find(|resource| resource.id == id)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        validate_atom(&self.ca.name)?;
        parse_duration_seconds(&self.ca.default_ttl)?;
        let ca_max_ttl = parse_duration_seconds(&self.ca.max_ttl)?;

        let mut principal_ids = HashSet::new();
        for principal in &self.principals {
            validate_atom(&principal.id)?;
            if !principal_ids.insert(principal.id.as_str()) {
                return Err(PolicyError::DuplicatePrincipalId {
                    id: principal.id.clone(),
                });
            }
            for ssh_principal in &principal.ssh_principals {
                validate_atom(ssh_principal)?;
            }
        }

        let mut resource_ids = HashSet::new();
        for resource in &self.resources {
            validate_atom(&resource.id)?;
            validate_atom(&resource.host)?;
            if !resource_ids.insert(resource.id.as_str()) {
                return Err(PolicyError::DuplicateResourceId {
                    id: resource.id.clone(),
                });
            }
        }

        if self.rules.len() > MAX_RULES {
            return Err(PolicyError::TooManyRules {
                actual: self.rules.len(),
                limit: MAX_RULES,
            });
        }

        let mut rule_names = HashSet::new();
        for rule in &self.rules {
            validate_atom(&rule.name)?;
            if !rule_names.insert(rule.name.as_str()) {
                return Err(PolicyError::DuplicateRuleName {
                    name: rule.name.clone(),
                });
            }

            let principal = required_selector(rule, "principal", rule.principal.as_deref())?;
            let action = required_selector(rule, "action", rule.action.as_deref())?;
            let resource = required_selector(rule, "resource", rule.resource.as_deref())?;

            validate_selector(principal)?;
            validate_selector(action)?;
            validate_selector(resource)?;
            if let Some(ssh_principal) = &rule.ssh_principal {
                validate_atom(ssh_principal)?;
            }

            if principal != ANY && !principal_ids.contains(principal) {
                return Err(PolicyError::UnknownPrincipal {
                    rule: rule.name.clone(),
                    principal: principal.to_string(),
                });
            }
            if resource != ANY && !resource_ids.contains(resource) {
                return Err(PolicyError::UnknownResource {
                    rule: rule.name.clone(),
                    resource: resource.to_string(),
                });
            }

            if let Some(max_ttl) = &rule.max_ttl {
                if parse_duration_seconds(max_ttl)? > ca_max_ttl {
                    return Err(PolicyError::TtlExceedsCaMax {
                        rule: rule.name.clone(),
                    });
                }
            }
        }

        Ok(())
    }
}

fn required_selector<'a>(
    rule: &'a RuleConfig,
    selector: &'static str,
    value: Option<&'a str>,
) -> Result<&'a str, PolicyError> {
    value.ok_or_else(|| PolicyError::MissingSelector {
        rule: rule.name.clone(),
        selector,
    })
}

fn validate_selector(value: &str) -> Result<(), PolicyError> {
    if value == ANY {
        Ok(())
    } else {
        validate_atom(value)
    }
}

pub fn validate_atom(value: &str) -> Result<(), PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::EmptyAtom {
            value: value.to_string(),
        });
    }
    if value.len() > MAX_ATOM_LEN {
        return Err(PolicyError::AtomTooLong {
            value: value.to_string(),
            limit: MAX_ATOM_LEN,
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        let allowed = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-');
        if !allowed {
            return Err(PolicyError::InvalidAtom {
                value: value.to_string(),
                index,
                byte,
            });
        }
    }
    Ok(())
}

pub fn parse_duration_seconds(value: &str) -> Result<u64, PolicyError> {
    if value.len() < 2 {
        return Err(PolicyError::InvalidDuration(value.to_string()));
    }
    let (number, suffix) = value.split_at(value.len() - 1);
    let number: u64 = number
        .parse()
        .map_err(|_| PolicyError::InvalidDuration(value.to_string()))?;
    match suffix {
        "s" => Ok(number),
        "m" => Ok(number * 60),
        "h" => Ok(number * 60 * 60),
        _ => Err(PolicyError::InvalidDuration(value.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_duration_minutes() {
        assert_eq!(parse_duration_seconds("5m").unwrap(), 300);
    }

    #[test]
    fn rejects_uppercase_atom() {
        assert!(matches!(
            validate_atom("User:Alice"),
            Err(PolicyError::InvalidAtom { .. })
        ));
    }

    #[test]
    fn parses_example_policy() {
        let policy = PolicyFile::from_yaml_str(include_str!("../examples/policy.yaml")).unwrap();
        assert_eq!(policy.rules.len(), 2);
    }

    #[test]
    fn rejects_duplicate_rule_names() {
        let yaml = r#"
version: 1
ca: { name: accessc-demo-ca, default_ttl: 5m, max_ttl: 15m }
principals: [{ id: user:alice, ssh_principals: [alice] }]
resources: [{ id: server:prod, host: prod-01, trusted_ca_path: /etc/ssh/accessc_ca.pub }]
rules:
  - { name: same, effect: allow, principal: user:alice, action: ssh, resource: server:prod }
  - { name: same, effect: deny, principal: any, action: ssh, resource: server:prod }
"#;
        assert!(matches!(
            PolicyFile::from_yaml_str(yaml),
            Err(PolicyError::DuplicateRuleName { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_principal_ids() {
        let yaml = r#"
version: 1
ca: { name: accessc-demo-ca, default_ttl: 5m, max_ttl: 15m }
principals:
  - { id: user:alice, ssh_principals: [alice] }
  - { id: user:alice, ssh_principals: [alice2] }
resources: [{ id: server:prod, host: prod-01, trusted_ca_path: /etc/ssh/accessc_ca.pub }]
rules:
  - { name: allow-alice-prod, effect: allow, principal: user:alice, action: ssh, resource: server:prod }
"#;
        assert!(matches!(
            PolicyFile::from_yaml_str(yaml),
            Err(PolicyError::DuplicatePrincipalId { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_resource_ids() {
        let yaml = r#"
version: 1
ca: { name: accessc-demo-ca, default_ttl: 5m, max_ttl: 15m }
principals: [{ id: user:alice, ssh_principals: [alice] }]
resources:
  - { id: server:prod, host: prod-01, trusted_ca_path: /etc/ssh/accessc_ca.pub }
  - { id: server:prod, host: prod-02, trusted_ca_path: /etc/ssh/accessc_ca.pub }
rules:
  - { name: allow-alice-prod, effect: allow, principal: user:alice, action: ssh, resource: server:prod }
"#;
        assert!(matches!(
            PolicyFile::from_yaml_str(yaml),
            Err(PolicyError::DuplicateResourceId { .. })
        ));
    }

    #[test]
    fn rejects_rule_with_omitted_selector() {
        let yaml = r#"
version: 1
ca: { name: accessc-demo-ca, default_ttl: 5m, max_ttl: 15m }
principals: [{ id: user:alice, ssh_principals: [alice] }]
resources: [{ id: server:prod, host: prod-01, trusted_ca_path: /etc/ssh/accessc_ca.pub }]
rules:
  - { name: bad, effect: allow, principal: user:alice, action: ssh }
"#;
        assert!(matches!(
            PolicyFile::from_yaml_str(yaml),
            Err(PolicyError::MissingSelector { .. })
        ));
    }
}
