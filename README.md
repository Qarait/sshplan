# accessc

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Compile access policy into OpenSSH config, issuance plans, and audit receipts.**

No proxy. No agent. No SaaS. No private CA key handling in the MVP.

`accessc` is a tiny OpenSSH access compiler. It takes a YAML policy, evaluates a request, and writes native OpenSSH artifacts you can inspect before anyone signs a certificate.

```bash
accessc check examples/policy.yaml
accessc compile examples/policy.yaml --out dist
accessc plan examples/policy.yaml --principal user:alice --resource server:prod --ttl 5m --ssh-principal alice --out dist
```

It generates OpenSSH-native output like:

```conf
TrustedUserCAKeys /etc/ssh/accessc_ca.pub
```

and a safe, non-executed signing plan:

```bash
ssh-keygen -s /path/to/ca_key -I accessc-user-alice-server-prod-alice -n alice -V +300s /path/to/user.pub
```

See [demo/terminal.md](demo/terminal.md) for a short terminal walkthrough.

## Why

Static SSH keys are easy to spread and hard to retire. Full access platforms are powerful, but often bring proxies, agents, hosted control planes, or broad operational scope. accessc takes a smaller route: keep OpenSSH native, keep the evaluator bounded, and make access decisions visible before anyone signs a certificate.

## Quick Start

```bash
git clone https://github.com/Qarait/accessc.git
cd accessc
cargo run -- check examples/policy.yaml
cargo run -- compile examples/policy.yaml --out dist
cargo run -- plan examples/policy.yaml --principal user:alice --resource server:prod --ttl 5m --ssh-principal alice --out dist
```

## What It Generates

- `dist/sshd/sshd_config.snippet`
- `dist/ssh/issue-command.txt`
- `dist/plans/user-alice-server-prod-alice-plan.json`
- `dist/audit/<timestamp>-receipt.json`

The MVP does not execute the generated `ssh-keygen` command. It generates the plan and receipt so operators can inspect what would happen.

## Policy Example

```yaml
rules:
  - name: allow-alice-prod
    effect: allow
    principal: user:alice
    action: ssh
    resource: server:prod
    max_ttl: 5m

  - name: deny-prod-root
    effect: deny
    principal: any
    action: ssh
    resource: server:prod
    ssh_principal: root
```

## What It Is Not

- Not an SSH proxy
- Not an agent
- Not a SaaS
- Not a certificate signer in the MVP
- Not a replacement for Teleport, Vault, Smallstep, or Cloudflare Access

## Comparison

| Tool | Best at | accessc difference |
| --- | --- | --- |
| Static SSH keys | Simple login | accessc plans short-lived certificate issuance |
| Vault SSH CA | Secrets platform CA | accessc is a local compiler, not a secrets platform |
| Smallstep | Certificate infrastructure | accessc focuses on OpenSSH access artifacts |
| Teleport | Full access platform | accessc avoids proxy, agent, and daemon scope |

## Lineage

From the creator of Ephemera, Gate0, and Gate1. Ephemera explored self-hosted SSH certificate access. Gate0 and Gate1 explored bounded authorization kernels. accessc compresses those lessons into a small OpenSSH access compiler.

## Status

MVP. The current version validates policy, evaluates access requests, compiles OpenSSH snippets, and writes safe issuance plans. Real certificate signing is intentionally out of scope for the first release.
