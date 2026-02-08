//! Build helper for udp-fanout.
//!
//! Handles compiling the eBPF program with the correct target and linker.
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]
//!   cargo xtask build [--release]        # Build both eBPF and userspace
//!   cargo xtask run [--release] -- <args> # Build everything and run

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the eBPF program only.
    BuildEbpf {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + userspace).
    Build {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build everything and run the daemon.
    Run {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
        /// Arguments to pass to udp-fanout.
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
        Cli::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)?;
        }
        Cli::Run { release, args } => {
            build_ebpf(release)?;
            build_userspace(release)?;
            run_daemon(release, &args)?;
        }
    }

    Ok(())
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Build the eBPF program.
///
/// This requires:
/// - `bpf-linker` installed: `cargo install bpf-linker`
/// - Nightly Rust for the BPF target: `rustup toolchain install nightly`
/// - BPF target: `rustup target add bpfel-unknown-none --toolchain nightly`
fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root();
    let ebpf_dir = root.join("udp-fanout-ebpf");

    println!("=> Building eBPF program...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir)
        .arg("+nightly")
        .arg("build")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("running cargo build for eBPF program")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    // Copy the compiled eBPF binary to the workspace root for easy access
    let profile = if release { "release" } else { "debug" };
    let ebpf_binary = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("udp-fanout-ebpf");

    let dest = root.join("target").join("udp-fanout-ebpf");
    std::fs::create_dir_all(dest.parent().unwrap())?;

    if ebpf_binary.exists() {
        std::fs::copy(&ebpf_binary, &dest).with_context(|| {
            format!(
                "copying eBPF binary from {} to {}",
                ebpf_binary.display(),
                dest.display()
            )
        })?;
        println!(
            "   eBPF program: {}",
            dest.display()
        );
    }

    println!("=> eBPF build complete");
    Ok(())
}

/// Build the userspace daemon.
fn build_userspace(release: bool) -> Result<()> {
    let root = workspace_root();

    println!("=> Building userspace daemon...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).arg("build").arg("-p").arg("udp-fanout");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("running cargo build for userspace")?;

    if !status.success() {
        bail!("userspace build failed");
    }

    println!("=> Userspace build complete");
    Ok(())
}

/// Run the daemon.
fn run_daemon(release: bool, extra_args: &[String]) -> Result<()> {
    let root = workspace_root();
    let profile = if release { "release" } else { "debug" };

    let binary = root.join("target").join(profile).join("udp-fanout");
    let ebpf_program = root.join("target").join("udp-fanout-ebpf");

    println!("=> Running udp-fanout...");

    let mut cmd = Command::new(&binary);
    cmd.arg("--ebpf-program").arg(&ebpf_program);
    cmd.args(extra_args);

    let status = cmd.status().context("running udp-fanout")?;

    if !status.success() {
        bail!("udp-fanout exited with error");
    }

    Ok(())
}
