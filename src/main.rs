use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod artifacts;
mod evaluator;
mod plan;
mod policy;

#[derive(Debug, Parser)]
#[command(name = "sshplan")]
#[command(about = "Compile access policy into OpenSSH config, issuance plans, and audit receipts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Check {
        policy: PathBuf,
    },
    Compile {
        policy: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Decide {
        policy: PathBuf,
        #[arg(long)]
        principal: String,
        #[arg(long)]
        action: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        ttl: String,
        #[arg(long)]
        ssh_principal: Option<String>,
    },
    Plan {
        policy: PathBuf,
        #[arg(long)]
        principal: String,
        #[arg(long, default_value = "ssh")]
        action: String,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        ttl: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        ssh_principal: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Check { policy } => {
            let policy = policy::PolicyFile::load(policy)?;
            println!("policy ok: {} rule(s)", policy.rules.len());
        }
        Command::Compile { policy, out } => {
            let policy = policy::PolicyFile::load(policy)?;
            artifacts::write_compile_artifacts(&policy, &out)?;
            println!("compiled OpenSSH artifacts to {}", out.display());
        }
        Command::Decide {
            policy,
            principal,
            action,
            resource,
            ttl,
            ssh_principal,
        } => {
            let policy = policy::PolicyFile::load(policy)?;
            let request = evaluator::Request::from_cli(
                &principal,
                &action,
                &resource,
                ssh_principal.as_deref(),
                &ttl,
            )?;
            let decision = evaluator::evaluate(&policy, &request)?;
            println!("{}", decision.summary());
            if !decision.is_allow() {
                std::process::exit(2);
            }
        }
        Command::Plan {
            policy,
            principal,
            action,
            resource,
            ttl,
            out,
            ssh_principal,
        } => {
            let policy = policy::PolicyFile::load(policy)?;
            let request = evaluator::Request::from_cli(
                &principal,
                &action,
                &resource,
                ssh_principal.as_deref(),
                &ttl,
            )?;
            let decision = evaluator::evaluate(&policy, &request)?;
            let plan = plan::build_plan(&policy, &request, &decision)?;
            artifacts::write_plan_artifacts(&policy, &request, &plan, &out)?;
            println!("planned OpenSSH certificate issuance to {}", out.display());
        }
    }
    Ok(())
}
