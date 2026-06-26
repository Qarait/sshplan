use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn compile_writes_openssh_artifacts() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("accessc")
        .unwrap()
        .args(["compile", "examples/policy.yaml", "--out"])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("compiled OpenSSH artifacts"));

    assert!(dir.path().join("ca/accessc_ca.pub").exists());
    assert!(dir.path().join("sshd/sshd_config.snippet").exists());
    assert!(dir.path().join("policy/compiled-policy.json").exists());
}

#[test]
fn plan_writes_safe_issuance_plan() {
    let dir = tempdir().unwrap();
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "plan",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "alice",
            "--out",
        ])
        .arg(dir.path())
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "planned OpenSSH certificate issuance",
        ));

    assert!(dir.path().join("ssh/issue-command.txt").exists());
    assert!(dir.path().join("ssh/config.snippet").exists());
}

#[test]
fn check_validates_policy() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args(["check", "examples/policy.yaml"])
        .assert()
        .success()
        .stdout(predicate::str::contains("policy ok"));
}

#[test]
fn decide_returns_allow() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "decide",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--action",
            "ssh",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "alice",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("allow"));
}

#[test]
fn decide_denies_root() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "decide",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--action",
            "ssh",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "root",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("deny"));
}

#[test]
fn decide_rejects_unlisted_ssh_principal() {
    Command::cargo_bin("accessc")
        .unwrap()
        .args([
            "decide",
            "examples/policy.yaml",
            "--principal",
            "user:alice",
            "--action",
            "ssh",
            "--resource",
            "server:prod",
            "--ttl",
            "5m",
            "--ssh-principal",
            "bob",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "ssh principal `bob` is not allowed for `user:alice`",
        ));
}

#[test]
fn compile_uses_policy_trusted_ca_path() {
    let policy_dir = tempdir().unwrap();
    let policy_path = policy_dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        r#"version: 1
ca:
  name: accessc-demo-ca
  default_ttl: 5m
  max_ttl: 15m
principals:
  - id: user:alice
    ssh_principals: [alice]
resources:
  - id: server:prod
    host: prod-01
    trusted_ca_path: /custom/ca.pub
rules:
  - name: allow-alice-prod
    effect: allow
    principal: user:alice
    action: ssh
    resource: server:prod
    max_ttl: 5m
"#,
    )
    .unwrap();
    let out = tempdir().unwrap();

    Command::cargo_bin("accessc")
        .unwrap()
        .arg("compile")
        .arg(&policy_path)
        .arg("--out")
        .arg(out.path())
        .assert()
        .success();

    let snippet = fs::read_to_string(out.path().join("sshd/sshd_config.snippet")).unwrap();
    assert!(snippet.contains("TrustedUserCAKeys /custom/ca.pub"));
}

#[test]
fn plan_keeps_distinct_ssh_principals_in_filenames() {
    let policy_dir = tempdir().unwrap();
    let policy_path = policy_dir.path().join("policy.yaml");
    fs::write(
        &policy_path,
        r#"version: 1
ca:
  name: accessc-demo-ca
  default_ttl: 5m
  max_ttl: 15m
principals:
  - id: user:alice
    ssh_principals: [alice, alice-admin]
resources:
  - id: server:prod
    host: prod-01
    trusted_ca_path: /etc/ssh/accessc_ca.pub
rules:
  - name: allow-alice-prod
    effect: allow
    principal: user:alice
    action: ssh
    resource: server:prod
    max_ttl: 5m
"#,
    )
    .unwrap();
    let out = tempdir().unwrap();

    for ssh_principal in ["alice", "alice-admin"] {
        Command::cargo_bin("accessc")
            .unwrap()
            .arg("plan")
            .arg(&policy_path)
            .args([
                "--principal",
                "user:alice",
                "--resource",
                "server:prod",
                "--ttl",
                "5m",
                "--ssh-principal",
                ssh_principal,
                "--out",
            ])
            .arg(out.path())
            .assert()
            .success();
    }

    assert!(out
        .path()
        .join("plans/user-alice-server-prod-alice-plan.json")
        .exists());
    assert!(out
        .path()
        .join("plans/user-alice-server-prod-alice-admin-plan.json")
        .exists());
}
