//! Storage: one encrypted SQLite file, with the overview/detail split from DESIGN §5.
//!
//! Every value column is a self-contained AEAD blob (nonce ‖ ciphertext) whose AAD binds it to
//! its slot, so ciphertext cannot be relocated between items, slots or vaults.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

use crate::{
    aad_item, check_canary, derive_master_key, make_canary, open, random_16, random_32,
    seal, AccountKey, Category, Detail, Error, KdfParams, Keys, Overview, Result,
};

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS meta   (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS vaults (id TEXT PRIMARY KEY, name_enc BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL,
    category TEXT NOT NULL,
    version INTEGER NOT NULL,
    overview_enc BLOB NOT NULL,
    detail_enc BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    favorite INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS item_keys (item_id TEXT PRIMARY KEY, wrapped_ik BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS items_vault ON items(vault_id);
"#;

/// Vault-scoped parameters (currently just the KDF cost, stored per vault for future rises).
#[derive(Debug, Clone, Copy, Default)]
pub struct VaultParams {
    pub kdf: KdfParams,
}

/// An unlocked vault: holds the subkeys for as long as the struct lives.
pub struct Vault {
    conn: Connection,
    keys: Keys,
    vault_id: String,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault({})", self.vault_id)
    }
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

impl Vault {
    /// Create a new vault. Returns the vault and the account key — the caller must show the
    /// recovery kit once, because it cannot be recovered from the file.
    pub fn create(path: &Path, passphrase: &str, params: VaultParams) -> Result<(Self, AccountKey)> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        restrict_permissions(path);

        let account_key = AccountKey::generate();
        let salt = random_16();
        let mk = derive_master_key(passphrase, &account_key, &salt, params.kdf)?;

        let enc = super::expand_enc_only(&mk)?;
        let vault_key = random_32();
        let wrapped_vk = seal(&enc, &vault_key, b"vk")?;
        let canary = make_canary(&enc)?;
        let vault_id = uuid::Uuid::new_v4().to_string();
        let name_enc = seal(&enc, b"personal", b"vault-name")?;

        let tx = conn.unchecked_transaction()?;
        for (k, v) in [
            ("salt", salt.to_vec()),
            ("kdf_m", params.kdf.m_cost_kib.to_le_bytes().to_vec()),
            ("kdf_t", params.kdf.t_cost.to_le_bytes().to_vec()),
            ("kdf_p", params.kdf.p_cost.to_le_bytes().to_vec()),
            ("wrapped_vk", wrapped_vk),
            ("canary", canary),
        ] {
            tx.execute("INSERT INTO meta(key, value) VALUES (?1, ?2)", params![k, v])?;
        }
        tx.execute(
            "INSERT INTO vaults(id, name_enc) VALUES (?1, ?2)",
            params![vault_id, name_enc],
        )?;
        tx.commit()?;

        Ok((
            Self {
                conn,
                keys: Keys {
                    enc: Zeroizing::new(enc),
                    mac: Zeroizing::new(super::expand_mac_only(&mk)?),
                    vault_key: Zeroizing::new(vault_key),
                },
                vault_id,
            },
            account_key,
        ))
    }

    /// Open and unlock. Fails with `BadCredentials` for a wrong passphrase *or* wrong account key,
    /// indistinguishable on purpose — the canary check happens before any item is touched.
    pub fn open(path: &Path, passphrase: &str, account_key: &AccountKey) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;

        let salt = meta_blob(&conn, "salt")?;
        let salt: [u8; 16] = salt.as_slice().try_into().map_err(|_| Error::MissingMeta("salt"))?;
        let params = KdfParams {
            m_cost_kib: meta_u32(&conn, "kdf_m")?,
            t_cost: meta_u32(&conn, "kdf_t")?,
            p_cost: meta_u32(&conn, "kdf_p")?,
        };
        let wrapped_vk = meta_blob(&conn, "wrapped_vk")?;
        let canary = meta_blob(&conn, "canary")?;

        let mk = derive_master_key(passphrase, account_key, &salt, params)?;
        let enc = crate::expand_enc_only(&mk)?;
        let mac = crate::expand_mac_only(&mk)?;

        // Canary first: a wrong passphrase or wrong account key must fail *here*, with an
        // unambiguous error, before any key material is unwrapped (DESIGN §4.4).
        check_canary(&enc, &canary)?;

        let vk_raw = open(&enc, &wrapped_vk, b"vk")?;
        let vault_key: [u8; 32] = vk_raw
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decrypt("vault key length"))?;
        let keys = Keys {
            enc: Zeroizing::new(enc),
            mac: Zeroizing::new(mac),
            vault_key: Zeroizing::new(vault_key),
        };

        let vault_id: String = conn
            .query_row("SELECT id FROM vaults LIMIT 1", [], |r| r.get(0))
            .optional()?
            .ok_or(Error::MissingMeta("vault row"))?;

        Ok(Self { conn, keys, vault_id })
    }

    /// Drop the keys. Anything already read stays read; this is not a memory scrub of the process.
    pub fn lock(self) {}

    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    pub fn count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM items WHERE deleted_at IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Insert an item. Overview and detail get separate keys' worth of ciphertext (DESIGN §5).
    pub fn insert(&mut self, category: Category, overview: &Overview, detail: &Detail) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let ik = random_32();
        let wrapped_ik = seal(&self.keys.enc, &ik, &aad_item(&id, "ik"))?;
        let overview_enc = seal(&ik, &serde_json::to_vec(overview)?, &aad_item(&id, "ov"))?;
        let detail_enc = seal(&ik, &serde_json::to_vec(detail)?, &aad_item(&id, "dt"))?;
        let ts = now_secs();

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO items(id, vault_id, category, version, overview_enc, detail_enc,
                               created_at, updated_at, favorite)
             VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, ?6, ?7)",
            params![
                id,
                self.vault_id,
                category.as_str(),
                overview_enc,
                detail_enc,
                ts,
                if overview.favorite { 1 } else { 0 }
            ],
        )?;
        tx.execute(
            "INSERT INTO item_keys(item_id, wrapped_ik) VALUES (?1, ?2)",
            params![id, wrapped_ik],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Cheap listing: decrypts overviews only. This is the whole point of the split.
    pub fn list(&self) -> Result<Vec<(String, Category, Overview)>> {
        let mut stmt = self.conn.prepare(
            "SELECT i.id, i.category, i.overview_enc, k.wrapped_ik
             FROM items i JOIN item_keys k ON k.item_id = i.id
             WHERE i.deleted_at IS NULL
             ORDER BY i.updated_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, cat, overview_enc, wrapped_ik) = row?;
            let ik = match open(&self.keys.enc, &wrapped_ik, &aad_item(&id, "ik")) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let ik: [u8; 32] = match ik.as_slice().try_into() {
                Ok(k) => k,
                Err(_) => continue,
            };
            if let Ok(pt) = open(&ik, &overview_enc, &aad_item(&id, "ov")) {
                if let Ok(ov) = serde_json::from_slice::<Overview>(&pt) {
                    out.push((id, Category::parse(&cat).unwrap_or(Category::Login), ov));
                }
            }
        }
        Ok(out)
    }

    /// Expensive read: unwraps the item key once, then the detail blob.
    pub fn get(&self, needle: &str) -> Result<(String, Category, Overview, Detail)> {
        let (id, cat, overview_enc, detail_enc, wrapped_ik) = self.find(needle)?;
        let ik: [u8; 32] = open(&self.keys.enc, &wrapped_ik, &aad_item(&id, "ik"))?
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decrypt("item key length"))?;
        let overview: Overview = serde_json::from_slice(&open(&ik, &overview_enc, &aad_item(&id, "ov"))?)?;
        let detail: Detail = serde_json::from_slice(&open(&ik, &detail_enc, &aad_item(&id, "dt"))?)?;
        Ok((id, Category::parse(&cat).unwrap_or(Category::Login), overview, detail))
    }

    /// Read one field — the projection a T1/T3 client gets, without the item body.
    pub fn field(&self, needle: &str, field: &str) -> Result<String> {
        let (_, _, _, detail) = self.get(needle)?;
        detail
            .fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(field))
            .map(|f| f.value.clone())
            .ok_or_else(|| Error::UnknownField(field.to_string()))
    }

    pub fn totp(&self, needle: &str) -> Result<(String, u64)> {
        let secret = self.field(needle, "totp")?;
        crate::totp_now(&secret, 0)
    }

    fn find(&self, needle: &str) -> Result<(String, String, Vec<u8>, Vec<u8>, Vec<u8>)> {
        // exact id, id prefix, then case-insensitive title search (title lives in the overview blob)
        let mut stmt = self.conn.prepare(
            "SELECT i.id, i.category, i.overview_enc, i.detail_enc, k.wrapped_ik
             FROM items i JOIN item_keys k ON k.item_id = i.id
             WHERE i.deleted_at IS NULL",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;

        let want = needle.to_ascii_lowercase();
        for row in rows {
            let (id, cat, ov_enc, dt_enc, wrap) = row?;
            if id == needle {
                return Ok((id, cat, ov_enc, dt_enc, wrap));
            }
            if id.starts_with(needle) {
                return Ok((id, cat, ov_enc, dt_enc, wrap));
            }
            if let Ok(ik) = open(&self.keys.enc, &wrap, &aad_item(&id, "ik")) {
                if let Ok(ik) = <[u8; 32]>::try_from(ik.as_slice()) {
                    if let Ok(pt) = open(&ik, &ov_enc, &aad_item(&id, "ov")) {
                        if let Ok(ov) = serde_json::from_slice::<Overview>(&pt) {
                            if ov.title.to_ascii_lowercase().contains(&want) {
                                return Ok((id, cat, ov_enc, dt_enc, wrap));
                            }
                        }
                    }
                }
            }
        }
        Err(Error::ItemNotFound(needle.to_string()))
    }
}

fn meta_blob(conn: &Connection, key: &str) -> Result<Vec<u8>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0))
        .optional()?
        .ok_or_else(|| Error::MissingMeta(if key == "salt" { "salt" } else { "meta" }))
}

fn meta_u32(conn: &Connection, key: &str) -> Result<u32> {
    let b = meta_blob(conn, key)?;
    let arr: [u8; 4] = b.as_slice().try_into().map_err(|_| Error::MissingMeta("kdf params"))?;
    Ok(u32::from_le_bytes(arr))
}

/// A vault file is secret material: owner-only, best effort (DESIGN §8).
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
