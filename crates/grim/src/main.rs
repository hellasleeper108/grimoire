//! `grim` — the GRIMOIRE client.
//!
//! P0a: the client speaks to `grim-core` in-process. The daemon (`grimd`) and the
//! Unix-socket capability layer are the next increment; the core API is already shaped for it
//! (Vault::open / list / get / field / totp are the verbs, not SQL).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use grim_core::{AccountKey, Category, Detail, Field, FieldKind, Overview, Vault, VaultParams};

#[derive(Parser)]
#[command(name = "grim", version, about = "GRIMOIRE — a book of secret names")]
struct Cli {
    /// Vault file (default: ~/.local/share/grimoire/vault.db)
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
    /// Account key file (default: ~/.config/grimoire/account.key)
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    /// Never print secrets unmasked
    #[arg(long, global = true)]
    no_reveal: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault and print the recovery kit (shown once)
    Init,
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
    /// List items (overviews only — the cheap half of the split)
    List,
    /// Read one item, or one field of it
    Get {
        needle: String,
        #[arg(long)]
        field: Option<String>,
    },
    /// Show the current TOTP code for an item
    Totp { needle: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("grim: {e}");
            ExitCode::FAILURE
        }
    }
}

fn vault_path(v: &Option<PathBuf>) -> PathBuf {
    v.clone().unwrap_or_else(|| data_dir().join("vault.db"))
}

fn key_path(k: &Option<PathBuf>) -> PathBuf {
    k.clone().unwrap_or_else(|| config_dir().join("account.key"))
}

fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

fn data_dir() -> PathBuf {
    home().join(".local/share/grimoire")
}

fn config_dir() -> PathBuf {
    home().join(".config/grimoire")
}

/// Passphrase from `GRIM_PASSPHRASE` when set (scripting), otherwise a hidden prompt.
fn passphrase(confirm: bool) -> grim_core::Result<String> {
    if let Ok(p) = std::env::var("GRIM_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(p);
        }
    }
    let first = rpassword::prompt_password("passphrase: ").unwrap_or_default();
    if first.is_empty() {
        return Err(grim_core::Error::BadCredentials);
    }
    if confirm {
        let second = rpassword::prompt_password("again: ").unwrap_or_default();
        if first != second {
            return Err(grim_core::Error::BadCredentials);
        }
    }
    Ok(first)
}

fn read_account_key(path: &PathBuf) -> grim_core::Result<AccountKey> {
    let raw = std::fs::read_to_string(path)?;
    AccountKey::parse(raw.trim())
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

fn run(cli: Cli) -> grim_core::Result<()> {
    let Cli { vault, key, no_reveal, cmd } = cli;
    let reveal = !no_reveal && std::env::var_os("GRIM_REVEAL").is_some_and(|v| v == "1");
    match cmd {
        Cmd::Init => {
            let vpath = vault_path(&vault);
            if vpath.exists() {
                eprintln!("grim: vault already exists at {}", vpath.display());
                return Err(grim_core::Error::BadCredentials);
            }
            let pass = passphrase(true)?;
            let (_vault, account_key) = Vault::create(&vpath, &pass, VaultParams::default())?;
            let recovery = account_key.to_recovery_string();
            write_private(&key_path(&key), &recovery)?;
            println!("vault created: {}", vpath.display());
            println!();
            println!("  RECOVERY KIT — write this down, it is not recoverable:");
            println!("    account key:  {recovery}");
            println!();
            println!("  A copy is on this device at {} (0600).", key_path(&key).display());
            println!("  The vault is unreadable without BOTH the passphrase and this key.");
        }
        Cmd::Add { category, title, username, password, url, totp, notes } => {
            let cat = Category::parse(&category).ok_or_else(|| {
                grim_core::Error::UnknownField(format!("category {category:?}"))
            })?;
            let pass = passphrase(false)?;
            let ak = read_account_key(&key_path(&key))?;
            let mut vault = Vault::open(&vault_path(&vault), &pass, &ak)?;

            let mut fields = Vec::new();
            if let Some(u) = username {
                fields.push(Field { name: "username".into(), kind: FieldKind::Text, value: u, conceal: false });
            }
            if let Some(p) = password {
                fields.push(Field { name: "password".into(), kind: FieldKind::Password, value: p, conceal: true });
            }
            if let Some(t) = totp {
                fields.push(Field { name: "totp".into(), kind: FieldKind::Totp, value: t, conceal: true });
            }
            if let Some(u) = url.clone() {
                fields.push(Field { name: "url".into(), kind: FieldKind::Url, value: u, conceal: false });
            }

            let overview = Overview {
                title,
                subtitle: username_or_empty(&fields),
                url_host: url.as_deref().map(host_of).unwrap_or_default(),
                tags: Vec::new(),
                favorite: false,
            };
            let detail = Detail { fields, notes: notes.unwrap_or_default() };
            let id = vault.insert(cat, &overview, &detail)?;
            println!("{}", &id[..8]);
        }
        Cmd::List => {
            let pass = passphrase(false)?;
            let ak = read_account_key(&key_path(&key))?;
            let vault = Vault::open(&vault_path(&vault), &pass, &ak)?;
            let items = vault.list()?;
            println!("{:<10} {:<11} {}", "ID", "CATEGORY", "TITLE  (subtitle)");
            for (id, cat, ov) in &items {
                let sub = if ov.subtitle.is_empty() { String::new() } else { format!("  ({})", ov.subtitle) };
                println!("{:<10} {:<11} {}{}", &id[..8], cat.as_str(), ov.title, sub);
            }
            println!("\n{} item(s)", items.len());
        }
        Cmd::Get { needle, field } => {
            let pass = passphrase(false)?;
            let ak = read_account_key(&key_path(&key))?;
            let vault = Vault::open(&vault_path(&vault), &pass, &ak)?;
            let (id, cat, ov, detail) = vault.get(&needle)?;
            match field {
                Some(name) => {
                    let f = detail
                        .fields
                        .iter()
                        .find(|f| f.name.eq_ignore_ascii_case(&name))
                        .ok_or_else(|| grim_core::Error::UnknownField(name.clone()))?;
                    println!("{}", mask_if(f, reveal));
                }
                None => {
                    println!("{}  [{}]  {}", &id[..8], cat.as_str(), ov.title);
                    if !ov.url_host.is_empty() {
                        println!("url_host: {}", ov.url_host);
                    }
                    for f in &detail.fields {
                        println!("{:<10} {}", f.name, mask_if(f, reveal));
                    }
                    if !detail.notes.is_empty() {
                        println!("\nnotes:\n{}", detail.notes);
                    }
                }
            }
        }
        Cmd::Totp { needle } => {
            let pass = passphrase(false)?;
            let ak = read_account_key(&key_path(&key))?;
            let vault = Vault::open(&vault_path(&vault), &pass, &ak)?;
            let (code, remaining) = vault.totp(&needle)?;
            println!("{code}  ({remaining}s left)");
        }
    }
    Ok(())
}

fn username_or_empty(fields: &[Field]) -> String {
    fields
        .iter()
        .find(|f| f.name == "username")
        .map(|f| f.value.clone())
        .unwrap_or_default()
}

fn host_of(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

fn mask_if(f: &Field, reveal: bool) -> String {
    if f.conceal && !reveal {
        format!("{}…  ({} chars; --reveal / GRIM_REVEAL=1 to show)", "•".repeat(8.min(f.value.len())), f.value.len())
    } else {
        f.value.clone()
    }
}
