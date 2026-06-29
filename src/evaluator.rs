use crate::policy::{parse_duration_seconds, validate_atom, Effect, PolicyError, PolicyFile, ANY};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvalError {
    #[error(transparent)]
    Policy(#[from] PolicyError),
    #[error("requested TTL exceeds allowed maximum of {max_seconds}s")]
    TtlTooLong { max_seconds: u64 },
    #[error("ssh principal `{ssh_principal}` is not allowed for `{principal}`")]
    SshPrincipalNotAllowed {
        principal: String,
        ssh_principal: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub ssh_principal: Option<String>,
    pub requested_ttl_seconds: u64,
}

impl Request {
    pub fn from_cli(
        principal: &str,
        action: &str,
        resource: &str,
        ssh_principal: Option<&str>,
        ttl: &str,
    ) -> Result<Self, EvalError> {
        validate_atom(principal)?;
        validate_atom(action)?;
        validate_atom(resource)?;
        if let Some(ssh_principal) = ssh_principal {
            validate_atom(ssh_principal)?;
        }
        Ok(Self {
            principal: principal.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            ssh_principal: ssh_principal.map(ToOwned::to_owned),
            requested_ttl_seconds: parse_duration_seconds(ttl)?,
        })
    }

    pub fn safe_name(&self) -> String {
        format!("{}-{}", sanitize(&self.principal), sanitize(&self.resource))
    }

    pub fn safe_name_for_ssh_principal(&self, ssh_principal: &str) -> String {
        format!("{}-{}", self.safe_name(), sanitize(ssh_principal))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { rule: String, ttl_seconds: u64 },
    Deny { rule: String },
    NoMatch,
}

impl Decision {
    pub fn summary(&self) -> String {
        match self {
            Decision::Allow { rule, ttl_seconds } => {
                format!("allow: rule={rule} ttl={ttl_seconds}s")
            }
            Decision::Deny { rule } => format!("deny: rule={rule}"),
            Decision::NoMatch => "no-match: no allow rule matched".to_string(),
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow { .. })
    }

    #[cfg(test)]
    pub fn rule_name(&self) -> Option<&str> {
        match self {
            Decision::Allow { rule, .. } | Decision::Deny { rule } => Some(rule.as_str()),
            Decision::NoMatch => None,
        }
    }

    #[cfg(test)]
    pub fn ttl_seconds(&self) -> Option<u64> {
        match self {
            Decision::Allow { ttl_seconds, .. } => Some(*ttl_seconds),
            _ => None,
        }
    }
}

pub fn evaluate(policy: &PolicyFile, request: &Request) -> Result<Decision, EvalError> {
    let ca_max_ttl = policy.ca_max_ttl_seconds()?;
    if request.requested_ttl_seconds > ca_max_ttl {
        return Err(EvalError::TtlTooLong {
            max_seconds: ca_max_ttl,
        });
    }

    for rule in &policy.rules {
        if !matches!(rule.effect, Effect::Deny) {
            continue;
        }
        if selector_matches(
            rule.principal.as_deref().expect("validated selector"),
            &request.principal,
        ) && selector_matches(
            rule.action.as_deref().expect("validated selector"),
            &request.action,
        ) && selector_matches(
            rule.resource.as_deref().expect("validated selector"),
            &request.resource,
        ) && ssh_principal_matches(
            rule.ssh_principal.as_deref(),
            request.ssh_principal.as_deref(),
        ) {
            return Ok(Decision::Deny {
                rule: rule.name.clone(),
            });
        }
    }

    let principal = match policy.principal(&request.principal) {
        Some(principal) => principal,
        None => return Ok(Decision::NoMatch),
    };

    if let Some(ssh_principal) = &request.ssh_principal {
        let allowed = principal
            .ssh_principals
            .iter()
            .any(|allowed| allowed == ssh_principal);
        if !allowed {
            return Err(EvalError::SshPrincipalNotAllowed {
                principal: request.principal.clone(),
                ssh_principal: ssh_principal.clone(),
            });
        }
    }

    let mut first_allow: Option<Decision> = None;
    for rule in &policy.rules {
        if !selector_matches(
            rule.principal.as_deref().expect("validated selector"),
            &request.principal,
        ) || !selector_matches(
            rule.action.as_deref().expect("validated selector"),
            &request.action,
        ) || !selector_matches(
            rule.resource.as_deref().expect("validated selector"),
            &request.resource,
        ) || !ssh_principal_matches(
            rule.ssh_principal.as_deref(),
            request.ssh_principal.as_deref(),
        ) {
            continue;
        }

        match rule.effect {
            Effect::Deny => {
                return Ok(Decision::Deny {
                    rule: rule.name.clone(),
                })
            }
            Effect::Allow => {
                if first_allow.is_none() {
                    let rule_ttl = match &rule.max_ttl {
                        Some(max_ttl) => parse_duration_seconds(max_ttl)?,
                        None => policy.ca_default_ttl_seconds()?,
                    };
                    if request.requested_ttl_seconds > rule_ttl {
                        return Err(EvalError::TtlTooLong {
                            max_seconds: rule_ttl,
                        });
                    }
                    first_allow = Some(Decision::Allow {
                        rule: rule.name.clone(),
                        ttl_seconds: request.requested_ttl_seconds.min(rule_ttl).min(ca_max_ttl),
                    });
                }
            }
        }
    }

    Ok(first_allow.unwrap_or(Decision::NoMatch))
}

fn selector_matches(selector: &str, candidate: &str) -> bool {
    selector == ANY || selector == candidate
}

fn ssh_principal_matches(selector: Option<&str>, candidate: Option<&str>) -> bool {
    match selector {
        Some(expected) => candidate == Some(expected),
        None => true,
    }
}

fn sanitize(value: &str) -> String {
    value.replace([':', '/', '.'], "-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PolicyFile {
        PolicyFile::from_yaml_str(include_str!("../examples/policy.yaml")).unwrap()
    }

    #[test]
    fn allows_alice_prod_ssh() {
        let request =
            Request::from_cli("user:alice", "ssh", "server:prod", Some("alice"), "5m").unwrap();
        let decision = evaluate(&policy(), &request).unwrap();
        assert!(decision.is_allow());
        assert_eq!(decision.rule_name(), Some("allow-alice-prod"));
        assert_eq!(decision.ttl_seconds(), Some(300));
    }

    #[test]
    fn deny_overrides_allow_for_root() {
        let request =
            Request::from_cli("user:alice", "ssh", "server:prod", Some("root"), "5m").unwrap();
        let decision = evaluate(&policy(), &request).unwrap();
        assert!(matches!(decision, Decision::Deny { .. }));
        assert_eq!(decision.rule_name(), Some("deny-prod-root"));
    }

    #[test]
    fn rejects_unlisted_ssh_principal() {
        let request =
            Request::from_cli("user:alice", "ssh", "server:prod", Some("bob"), "5m").unwrap();
        assert!(matches!(
            evaluate(&policy(), &request),
            Err(EvalError::SshPrincipalNotAllowed { .. })
        ));
    }

    #[test]
    fn no_match_is_not_allow() {
        let request =
            Request::from_cli("user:alice", "ssh", "server:missing", Some("alice"), "5m").unwrap();
        let decision = evaluate(&policy(), &request).unwrap();
        assert!(matches!(decision, Decision::NoMatch));
        assert!(!decision.is_allow());
    }

    #[test]
    fn requested_ttl_must_fit_rule() {
        let request =
            Request::from_cli("user:alice", "ssh", "server:prod", Some("alice"), "6m").unwrap();
        assert!(matches!(
            evaluate(&policy(), &request),
            Err(EvalError::TtlTooLong { max_seconds: 300 })
        ));
    }
}
