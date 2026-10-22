//! `grimd` entry point: bind the socket, then serve.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use clap::Parser;
use grim_core::AccountKey;
use grimd::{prepare_socket, serve, State};

#[derive(Parser)]
#[command(name = "grimd", version, about = "GRIMOIRE daemon — owns the keys, answers capability verbs")]
struct Cli {
    /// Vault file
    #[arg(long)]
    vault: Option<PathBuf>,
    /// Account key file
    #[arg(long)]
    key: Option<PathBuf>,
    /// Unix socket to listen on
    #[arg(long)]
    socket: Option<PathBuf>,
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn default_socket() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        let mut p = PathBuf::from(runtime);
        p.push("grimoire/grimd.sock");
        return p;
    }
    home().join(".local/share/grimoire/grimd.sock")
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let vault = cli.vault.unwrap_or_else(|| home().join(".local/share/grimoire/vault.db"));
    let key_path = cli.key.unwrap_or_else(|| home().join(".config/grimoire/account.key"));
    let socket = cli.socket.unwrap_or_else(default_socket);

    let raw = match std::fs::read_to_string(&key_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("grimd: cannot read account key {}: {e}", key_path.display());
            return ExitCode::FAILURE;
        }
    };
    let account_key = match AccountKey::parse(raw.trim()) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("grimd: bad account key: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = prepare_socket(&socket) {
        eprintln!("grimd: cannot prepare {}: {e}", socket.display());
        return ExitCode::FAILURE;
    }
    let listener = match std::os::unix::net::UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("grimd: cannot bind {}: {e}", socket.display());
            return ExitCode::FAILURE;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    }

    println!("grimd listening on {}", socket.display());
    println!("vault: {} (locked)", vault.display());
    serve(listener, Arc::new(Mutex::new(State::new(vault, account_key))));
    ExitCode::SUCCESS
}
