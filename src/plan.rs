use crate::evaluator::{Decision, Request};
use crate::policy::{PolicyError, PolicyFile};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PlanError {
    #[error("cannot plan certificate issuance for decision: {0}")]
    NotAllowed(String),
    #[error("unknown principal `{0}`")]
    UnknownPrincipal(String),
    #[error("unknown resource `{0}`")]
    UnknownResource(String),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[derive(Debug, Clone, Serialize)]
pub struct IssuancePlan {
    pub plan_id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub host: String,
    pub ssh_principal: String,
    pub ttl_seconds: u64,
    pub matched_rule: String,
    pub trusted_ca_path: String,
    pub issue_command: String,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReceipt {
    pub event: &'static str,
    pub decision: &'static str,
    pub plan_id: String,
    pub principal: String,
    pub action: String,
    pub resource: String,
    pub ssh_principal: String,
    pub ttl_seconds: u64,
    pub matched_rule: String,
    pub created_at_unix: u64,
}

pub fn build_plan(
    policy: &PolicyFile,
    request: &Request,
    decision: &Decision,
) -> Result<IssuancePlan, PlanError> {
    let (matched_rule, ttl_seconds) = match decision {
        Decision::Allow { rule, ttl_seconds } => (rule.clone(), *ttl_seconds),
        other => return Err(PlanError::NotAllowed(other.summary())),
    };

    let principal = policy
        .principal(&request.principal)
        .ok_or_else(|| PlanError::UnknownPrincipal(request.principal.clone()))?;
    let resource = policy
        .resource(&request.resource)
        .ok_or_else(|| PlanError::UnknownResource(request.resource.clone()))?;

    let ssh_principal = match &request.ssh_principal {
        Some(value) => value.clone(),
        None => principal
            .ssh_principals
            .first()
            .cloned()
            .ok_or_else(|| PlanError::UnknownPrincipal(request.principal.clone()))?,
    };
    let created_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let plan_id = request.safe_name_for_ssh_principal(&ssh_principal);
    let cert_identity = format!("sshplan-{}", plan_id);
    let issue_command = format!(
        "ssh-keygen -s /path/to/ca_key -I {cert_identity} -n {ssh_principal} -V +{ttl_seconds}s /path/to/user.pub"
    );

    Ok(IssuancePlan {
        plan_id,
        principal: request.principal.clone(),
        action: request.action.clone(),
        resource: request.resource.clone(),
        host: resource.host.clone(),
        ssh_principal,
        ttl_seconds,
        matched_rule,
        trusted_ca_path: resource.trusted_ca_path.clone(),
        issue_command,
        created_at_unix,
    })
}

impl IssuancePlan {
    pub fn audit_receipt(&self) -> AuditReceipt {
        AuditReceipt {
            event: "certificate_issuance_planned",
            decision: "allow",
            plan_id: self.plan_id.clone(),
            principal: self.principal.clone(),
            action: self.action.clone(),
            resource: self.resource.clone(),
            ssh_principal: self.ssh_principal.clone(),
            ttl_seconds: self.ttl_seconds,
            matched_rule: self.matched_rule.clone(),
            created_at_unix: self.created_at_unix,
        }
    }
}
