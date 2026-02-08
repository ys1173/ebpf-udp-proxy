//! Build helper for udp-fanout.
//!
//! Handles compiling the eBPF programs with the correct target and linker.
//!
//! Usage:
//!   cargo xtask build-ebpf [--release]         # Build TC eBPF program
//!   cargo xtask build-ebpf-xdp [--release]     # Build XDP eBPF program
//!   cargo xtask build [--release]              # Build everything (eBPF + XDP + userspace)
//!   cargo xtask run [--release] -- <args>      # Build everything and run

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    /// Build the TC eBPF program only.
    BuildEbpf {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build the XDP eBPF program only (for AF_XDP mode).
    BuildEbpfXdp {
        /// Build in release mode.
        #[arg(long)]
        release: bool,
    },
    /// Build everything (TC eBPF + XDP eBPF + userspace).
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
        Cli::BuildEbpfXdp { release } => {
            build_ebpf_xdp(release)?;
        }
        Cli::Build { release } => {
            build_ebpf(release)?;
            build_ebpf_xdp(release)?;
            build_userspace(release)?;
        }
        Cli::Run { release, args } => {
            build_ebpf(release)?;
            build_ebpf_xdp(release)?;
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

/// Build the TC eBPF program.
///
/// This requires:
/// - `bpf-linker` installed: `cargo install bpf-linker`
/// - Nightly Rust for the BPF target: `rustup toolchain install nightly`
/// - BPF target: `rustup target add bpfel-unknown-none --toolchain nightly`
fn build_ebpf(release: bool) -> Result<()> {
    let root = workspace_root();
    let ebpf_dir = root.join("udp-fanout-ebpf");

    println!("=> Building TC eBPF program...");

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

    let status = cmd.status().context("running cargo build for TC eBPF program")?;

    if !status.success() {
        bail!("TC eBPF build failed");
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
                "copying TC eBPF binary from {} to {}",
                ebpf_binary.display(),
                dest.display()
            )
        })?;
        println!("   TC eBPF program: {}", dest.display());
    }

    println!("=> TC eBPF build complete");
    Ok(())
}

/// Build the XDP eBPF program for AF_XDP mode.
///
/// Same toolchain requirements as build_ebpf.
fn build_ebpf_xdp(release: bool) -> Result<()> {
    let root = workspace_root();
    let xdp_dir = root.join("udp-fanout-ebpf-xdp");

    println!("=> Building XDP eBPF program...");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&xdp_dir)
        .arg("+nightly")
        .arg("build")
        .arg("--target=bpfel-unknown-none")
        .arg("-Z")
        .arg("build-std=core");

    if release {
        cmd.arg("--release");
    }

    let status = cmd.status().context("running cargo build for XDP eBPF program")?;

    if !status.success() {
        bail!("XDP eBPF build failed");
    }

    let profile = if release { "release" } else { "debug" };
    let xdp_binary = xdp_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("udp-fanout-ebpf-xdp");

    let dest = root.join("target").join("udp-fanout-ebpf-xdp");
    std::fs::create_dir_all(dest.parent().unwrap())?;

    if xdp_binary.exists() {
        std::fs::copy(&xdp_binary, &dest).with_context(|| {
            format!(
                "copying XDP eBPF binary from {} to {}",
                xdp_binary.display(),
                dest.display()
            )
        })?;
        println!("   XDP eBPF program: {}", dest.display());
    }

    println!("=> XDP eBPF build complete");
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
    let xdp_program = root.join("target").join("udp-fanout-ebpf-xdp");

    println!("=> Running udp-fanout...");

    let mut cmd = Command::new(&binary);
    cmd.arg("--ebpf-program").arg(&ebpf_program);
    cmd.arg("--xdp-program").arg(&xdp_program);
    cmd.args(extra_args);

    let status = cmd.status().context("running udp-fanout")?;

    if !status.success() {
        bail!("udp-fanout exited with error");
    }

    Ok(())
}
