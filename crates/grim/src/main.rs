//! `grim` — the GRIMOIRE client.
//!
//! Since P0b the client holds no keys and opens no database: every operation is a capability
//! verb sent to `grimd` (DESIGN §2). If the daemon isn't running this fails loudly rather than
//! quietly falling back to touching the vault in-process.
//!
//! `init` is the one exception: it *creates* the vault, so it runs before any daemon exists.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use grim_core::protocol::{call, Request, Response};
use grim_core::{Detail, Error, Field, FieldKind, Overview, Result, Vault, VaultParams};

mod clipboard;
mod tui;

#[derive(Parser)]
#[command(name = "grim", version, about = "GRIMOIRE — a book of secret names")]
struct Cli {
    /// Daemon socket (default: $XDG_RUNTIME_DIR/grimoire/grimd.sock)
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Vault file (used by `init` only)
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Account key file (used by `init` only)
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    /// Print secrets unmasked
    #[arg(long, global = true)]
    reveal: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault and print the recovery kit (shown once)
    Init,
    /// Interactive TUI over the daemon
    Tui {
        /// Render one frame as text and exit (for review and CI)
        #[arg(long)]
        snapshot: bool,
    },
    /// Daemon state: locked or not, item count, vault path
    Status,
    /// Unlock the daemon (passphrase from GRIM_PASSPHRASE or prompt)
    Unlock,
    /// Drop the keys
    Lock,
    /// List items (overviews only)
    List,
    /// Read one item, or one field of it
    Get {
        needle: String,
        #[arg(long)]
        field: Option<String>,
    },
    /// Current TOTP code for an item
    Totp { needle: String },
    /// Add an item
    Add {
        #[arg(long, default_value = "login")]
        category: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        totp: Option<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Stop the daemon
    Quit,
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn socket_path(cli: &Cli) -> PathBuf {
    cli.socket.clone().unwrap_or_else(|| {
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            let mut p = PathBuf::from(runtime);
            p.push("grimoire/grimd.sock");
            p
        } else {
            home().join(".local/share/grimoire/grimd.sock")
        }
    })
}

fn default_vault() -> PathBuf {
    home().join(".local/share/grimoire/vault.db")
}

fn default_key() -> PathBuf {
    home().join(".config/grimoire/account.key")
}

/// Passphrase from `GRIM_PASSPHRASE` when set (scripting), otherwise a hidden prompt.
fn passphrase(confirm: bool) -> Result<String> {
    if let Ok(p) = std::env::var("GRIM_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let first = rpassword::prompt_password("passphrase: ").unwrap_or_default();
    if first.is_empty() {
        return Err(Error::BadCredentials);
    }
    if confirm {
        let second = rpassword::prompt_password("again: ").unwrap_or_default();
        if first != second {
            return Err(Error::BadCredentials);
        }
    }
    Ok(first)
}

fn write_private(path: &PathBuf, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn ok_or_daemon_error(resp: Response) -> Result<Response> {
    match resp {
        Response::Error { message } => Err(Error::Daemon(message)),
        other => Ok(other),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("grim: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<()> {
    let reveal = cli.reveal || std::env::var_os("GRIM_REVEAL").is_some_and(|v| v == "1");

    // Vault creation happens before any daemon exists, so this one verb stays local.
    if matches!(cli.cmd, Cmd::Init) {
        let vpath = cli.vault.clone().unwrap_or_else(default_vault);
        if vpath.exists() {
            return Err(Error::Daemon(format!("vault already exists at {}", vpath.display())));
        }
        let pass = passphrase(true)?;
        let (_vault, account_key) = Vault::create(&vpath, &pass, VaultParams::default())?;
        let recovery = account_key.to_recovery_string();
        let keyfile = cli.key.clone().unwrap_or_else(default_key);
        write_private(&keyfile, &recovery)?;
        println!("vault created: {}", vpath.display());
        println!();
        println!("  RECOVERY KIT — write this down, it is not recoverable:");
        println!("    account key:  {recovery}");
        println!();
        println!("  A copy is on this device at {} (0600).", keyfile.display());
        println!("  The vault is unreadable without BOTH the passphrase and this key.");
        return Ok(());
    }

    let sock = socket_path(cli);
    if let Cmd::Tui { snapshot } = cli.cmd {
        return if snapshot {
            print!("{}", tui::snapshot(&sock, 100, 24)?);
            Ok(())
        } else {
            tui::run(&sock)
        };
    }
    let req = match &cli.cmd {
        Cmd::Init | Cmd::Tui { .. } => unreachable!("handled above"),
        Cmd::Status => Request::Status,
        Cmd::Unlock => Request::Unlock { passphrase: passphrase(false)? },
        Cmd::Lock => Request::Lock,
        Cmd::List => Request::ListItems,
        Cmd::Get { needle, field } => match field {
            Some(f) => Request::RevealField { needle: needle.clone(), field: f.clone() },
            None => Request::GetItem { needle: needle.clone() },
        },
        Cmd::Totp { needle } => Request::TotpNow { needle: needle.clone() },
        Cmd::Quit => Request::Quit,
        Cmd::Add { category, title, username, password, url, totp, notes } => {
            let mut fields = Vec::new();
            if let Some(u) = username {
                fields.push(Field {
                    name: "username".into(),
                    kind: FieldKind::Text,
                    value: u.clone(),
                    conceal: false,
                });
            }
            if let Some(p) = password {
                fields.push(Field {
                    name: "password".into(),
                    kind: FieldKind::Password,
                    value: p.clone(),
                    conceal: true,
                });
            }
            if let Some(t) = totp {
                fields.push(Field {
                    name: "totp".into(),
                    kind: FieldKind::Totp,
                    value: t.clone(),
                    conceal: true,
                });
            }
            if let Some(u) = url {
                fields.push(Field {
                    name: "url".into(),
                    kind: FieldKind::Url,
                    value: u.clone(),
                    conceal: false,
                });
            }
            Request::AddItem {
                category: category.clone(),
                overview: Overview {
                    title: title.clone(),
                    subtitle: username.clone().unwrap_or_default(),
                    url_host: url.as_deref().map(host_of).unwrap_or_default(),
                    tags: Vec::new(),
                    favorite: false,
                },
                detail: Detail { fields, notes: notes.clone().unwrap_or_default() },
            }
        }
    };

    let resp = ok_or_daemon_error(call(&sock, &req)?)?;
    render(cli, resp, reveal)
}

fn render(cli: &Cli, resp: Response, reveal: bool) -> Result<()> {
    match resp {
        Response::Ok => println!("ok"),
        Response::Status { locked, items, vault } => {
            println!("state:  {}", if locked { "locked" } else { "unlocked" });
            println!("vault:  {vault}");
            if !locked {
                println!("items:  {items}");
            }
        }
        Response::Items { items } => {
            println!("{:<10} {:<11} {}", "ID", "CATEGORY", "TITLE  (subtitle)");
            for row in &items {
                let sub = if row.subtitle.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", row.subtitle)
                };
                println!("{:<10} {:<11} {}{}", short(&row.id), row.category, row.title, sub);
            }
            println!("\n{} item(s)", items.len());
        }
        Response::Item { id, category, overview, detail } => match requested_field(cli) {
            Some(name) => {
                let f = detail
                    .fields
                    .iter()
                    .find(|x| x.name.eq_ignore_ascii_case(&name))
                    .ok_or_else(|| Error::UnknownField(name.clone()))?;
                println!("{}", mask(f, reveal));
            }
            None => {
                println!("{}  [{}]  {}", short(&id), category, overview.title);
                if !overview.url_host.is_empty() {
                    println!("url_host: {}", overview.url_host);
                }
                for f in &detail.fields {
                    println!("{:<10} {}", f.name, mask(f, reveal));
                }
                if !detail.notes.is_empty() {
                    println!("\nnotes:\n{}", detail.notes);
                }
            }
        },
        Response::Value { value } => println!("{value}"),
        Response::Totp { code, remaining } => println!("{code}  ({remaining}s left)"),
        Response::Added { id } => println!("{}", short(&id)),
        Response::Error { message } => return Err(Error::Daemon(message)),
    }
    Ok(())
}

fn requested_field(cli: &Cli) -> Option<String> {
    match &cli.cmd {
        Cmd::Get { field, .. } => field.clone(),
        _ => None,
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn host_of(url: &str) -> String {
    url.split("://").nth(1).unwrap_or(url).split('/').next().unwrap_or("").to_string()
}

fn mask(f: &Field, reveal: bool) -> String {
    if f.conceal && !reveal {
        format!(
            "{}…  ({} chars; --reveal or GRIM_REVEAL=1 to show)",
            "•".repeat(8.min(f.value.len())),
            f.value.len()
        )
    } else {
        f.value.clone()
    }
}
