//! grim-core — the fat core.
//!
//! Everything that touches a secret lives here: key derivation, envelope encryption,
//! the overview/detail item split, TOTP. The view (TUI/CLI) never implements crypto.
//!
//! Design references are to DESIGN.md in the repository root.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub mod import;
pub mod protocol;
pub mod store;
pub use import::{ImportReport, NewItem, Skipped};
pub use store::{Vault, VaultParams};

// ---------------------------------------------------------------- errors

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong passphrase or account key")]
    BadCredentials,
    #[error("vault file is not a grimoire vault (missing meta: {0})")]
    MissingMeta(&'static str),
    #[error("decryption failed: {0}")]
    Decrypt(&'static str),
    #[error("no item matching {0:?}")]
    ItemNotFound(String),
    #[error("unknown field {0:?}")]
    UnknownField(String),
    #[error("bad account key encoding")]
    BadAccountKey,
    #[error("bad base32 secret")]
    BadTotpSecret,
    #[error("storage: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("encoding: {0}")]
    Json(#[from] serde_json::Error),
    #[error("kdf: {0}")]
    Kdf(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("daemon: {0}")]
    Daemon(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// ---------------------------------------------------------------- kdf

/// Argon2id cost parameters, stored per vault so they can rise over time (DESIGN §4.2).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // 64 MiB, t=3, p=4 — DESIGN §4.2
        Self { m_cost_kib: 64 * 1024, t_cost: 3, p_cost: 4 }
    }
}

impl KdfParams {
    /// Cheap profile for tests only. Never a default.
    pub fn fast_for_tests() -> Self {
        Self { m_cost_kib: 8 * 1024, t_cost: 1, p_cost: 1 }
    }
}

const HKDF_MK: &[u8] = b"grimoire/mk/v1";
const HKDF_ENC: &[u8] = b"grimoire/kenc/v1";
const HKDF_MAC: &[u8] = b"grimoire/kmac/v1";
const CANARY_PLAINTEXT: &[u8] = b"grimoire-canary-v1";

/// 160-bit account key, printed on the recovery kit (DESIGN §4.3).
#[derive(Clone, Zeroize)]
pub struct AccountKey(pub [u8; 20]);

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AccountKey(<redacted>)")
    }
}

impl AccountKey {
    pub fn generate() -> Self {
        let mut b = [0u8; 20];
        rand::rngs::OsRng.fill_bytes(&mut b);
        Self(b)
    }

    /// `GR1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` — 32 base32 chars in 8 groups of 4.
    pub fn to_recovery_string(&self) -> String {
        let b32 = base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &self.0);
        let mut out = String::from("GR1");
        for chunk in b32.as_bytes().chunks(4) {
            out.push('-');
            out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        }
        out
    }

    pub fn parse(s: &str) -> Result<Self> {
        let cleaned: String = s.chars().filter(|c| *c != '-').collect();
        let body = cleaned.strip_prefix("GR1").ok_or(Error::BadAccountKey)?;
        let raw = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, body)
            .ok_or(Error::BadAccountKey)?;
        let arr: [u8; 20] = raw.as_slice().try_into().map_err(|_| Error::BadAccountKey)?;
        Ok(Self(arr))
    }
}

/// The three subkeys derived from the master key. Dropped (and zeroized) on lock.
pub struct Keys {
    pub enc: Zeroizing<[u8; 32]>,
    pub mac: Zeroizing<[u8; 32]>,
    pub vault_key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Keys(<redacted>)")
    }
}

/// MK = HKDF-SHA256(ikm = account_key, salt = Argon2id(passphrase), info = "grimoire/mk/v1").
///
/// Two secrets: the passphrase memory and the account key the attacker does not have
/// (DESIGN §4.1). A stolen vault file alone is not brute-forceable.
pub fn derive_master_key(
    passphrase: &str,
    account_key: &AccountKey,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<Zeroizing<[u8; 32]>> {
    let argon_params = argon2::Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon_params);
    let mut kdf_out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, kdf_out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(kdf_out.as_ref()), &account_key.0);
    let mut mk = Zeroizing::new([0u8; 32]);
    hk.expand(HKDF_MK, mk.as_mut()).map_err(|_| Error::Kdf("hkdf".into()))?;
    Ok(mk)
}

/// Expand the master key into purpose-separated subkeys plus the unwrapped vault key.
pub fn expand(mk: &[u8; 32], wrapped_vault_key: &[u8]) -> Result<Keys> {
    let enc = expand_label(mk, HKDF_ENC)?;
    let mac = expand_label(mk, HKDF_MAC)?;
    let vault_key_raw = open(&enc, wrapped_vault_key, b"vk")?;
    let vault_key: [u8; 32] = vault_key_raw
        .as_slice()
        .try_into()
        .map_err(|_| Error::Decrypt("vault key length"))?;
    Ok(Keys { enc: Zeroizing::new(enc), mac: Zeroizing::new(mac), vault_key: Zeroizing::new(vault_key) })
}

fn expand_label(mk: &[u8; 32], info: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"grimoire/salt/v1"), mk);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).map_err(|_| Error::Kdf("hkdf-expand".into()))?;
    Ok(out)
}

pub(crate) fn expand_enc_only(mk: &[u8; 32]) -> Result<[u8; 32]> {
    expand_label(mk, HKDF_ENC)
}

pub(crate) fn expand_mac_only(mk: &[u8; 32]) -> Result<[u8; 32]> {
    expand_label(mk, HKDF_MAC)
}

// ---------------------------------------------------------------- aead

/// XChaCha20-Poly1305, output = nonce (24 B) ‖ ciphertext. Random nonce is safe here
/// because XChaCha's 192-bit nonce makes collisions negligible (DESIGN §4.2).
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::Decrypt("seal"))?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return Err(Error::Decrypt("short ciphertext"));
    }
    let (nonce, ct) = sealed.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt("open"))
}

/// The canary: a fixed plaintext sealed under the enc key, so a wrong passphrase fails
/// immediately and unambiguously instead of showing a decryption error later (DESIGN §4.4).
pub fn make_canary(enc: &[u8; 32]) -> Result<Vec<u8>> {
    seal(enc, CANARY_PLAINTEXT, b"canary")
}

pub fn check_canary(enc: &[u8; 32], canary: &[u8]) -> Result<()> {
    let pt = open(enc, canary, b"canary").map_err(|_| Error::BadCredentials)?;
    if pt != CANARY_PLAINTEXT {
        return Err(Error::BadCredentials);
    }
    Ok(())
}

// ---------------------------------------------------------------- item model

/// Categories, shape borrowed from the taxonomy observed in 1Password (DESIGN §1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Login,
    Password,
    SecureNote,
    CreditCard,
    Identity,
    SshKey,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Login => "login",
            Category::Password => "password",
            Category::SecureNote => "securenote",
            Category::CreditCard => "creditcard",
            Category::Identity => "identity",
            Category::SshKey => "sshkey",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "login" => Category::Login,
            "password" => Category::Password,
            "securenote" | "secure_note" | "note" => Category::SecureNote,
            "creditcard" | "credit_card" | "card" => Category::CreditCard,
            "identity" => Category::Identity,
            "sshkey" | "ssh_key" | "ssh" => Category::SshKey,
            _ => return None,
        })
    }
}

/// What a list row needs — decrypted for every row (the cheap half).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    pub title: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub url_host: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
}

/// What only the selected item needs (the expensive half).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detail {
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub kind: FieldKind,
    pub value: String,
    #[serde(default)]
    pub conceal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldKind {
    Text,
    Password,
    Totp,
    Url,
    Markdown,
}

impl FieldKind {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "password" | "pass" => FieldKind::Password,
            "totp" | "otp" => FieldKind::Totp,
            "url" => FieldKind::Url,
            "markdown" | "note" | "notes" => FieldKind::Markdown,
            _ => FieldKind::Text,
        }
    }
}

// ---------------------------------------------------------------- totp

/// RFC 6238 TOTP over a base32 secret. SHA-1, 6 digits, 30 s — what the seeds in the wild use.
pub fn totp_now(secret_b32: &str, skew_steps: i64) -> Result<(String, u64)> {
    let cleaned: String = secret_b32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .collect::<String>()
        .to_ascii_uppercase();
    let key = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .ok_or(Error::BadTotpSecret)?;
    if key.is_empty() {
        return Err(Error::BadTotpSecret);
    }
    let period: u64 = 30;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Decrypt("clock"))?
        .as_secs();
    let counter = (now / period) as i64 + skew_steps;
    let code = hotp(&key, counter as u64)?;
    let remaining = period - (now % period);
    Ok((code, remaining))
}

fn hotp(key: &[u8], counter: u64) -> Result<String> {
    use hmac::{Hmac, Mac};
    type HmacSha1 = Hmac<sha1::Sha1>;
    let mut mac = <HmacSha1 as Mac>::new_from_slice(key).map_err(|_| Error::BadTotpSecret)?;
    mac.update(&counter.to_be_bytes());
    let sum = mac.finalize().into_bytes();
    let off = (sum[19] & 0x0f) as usize;
    let bin = ((sum[off] as u32 & 0x7f) << 24)
        | ((sum[off + 1] as u32) << 16)
        | ((sum[off + 2] as u32) << 8)
        | (sum[off + 3] as u32);
    Ok(format!("{:06}", bin % 1_000_000))
}

// ---------------------------------------------------------------- helpers

/// AAD that binds ciphertext to its slot: overview, detail, or wrapped item key.
pub(crate) fn aad_item(item_id: &str, what: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(what.len() + item_id.len() + 2);
    v.extend_from_slice(what.as_bytes());
    v.push(b'|');
    v.extend_from_slice(item_id.as_bytes());
    v
}

pub(crate) fn random_32() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

pub(crate) fn random_16() -> [u8; 16] {
    let mut k = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk() -> (AccountKey, [u8; 16], Zeroizing<[u8; 32]>) {
        let ak = AccountKey::generate();
        let salt = random_16();
        let mk = derive_master_key("correct horse battery staple", &ak, &salt, KdfParams::fast_for_tests()).unwrap();
        (ak, salt, mk)
    }

    #[test]
    fn account_key_roundtrip() {
        let ak = AccountKey::generate();
        let s = ak.to_recovery_string();
        assert!(s.starts_with("GR1-"));
        assert_eq!(s.len(), 3 + 8 * 5);
        assert_eq!(AccountKey::parse(&s).unwrap().0, ak.0);
        assert!(AccountKey::parse("GR1-ZZZZ").is_err());
    }

    #[test]
    fn derivation_is_deterministic_and_salt_bound() {
        let (ak, salt, k1) = mk();
        let k2 = derive_master_key("correct horse battery staple", &ak, &salt, KdfParams::fast_for_tests()).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());

        let salt2 = random_16();
        let k3 = derive_master_key("correct horse battery staple", &ak, &salt2, KdfParams::fast_for_tests()).unwrap();
        assert_ne!(k1.as_ref(), k3.as_ref());

        let other = AccountKey::generate();
        let k4 = derive_master_key("correct horse battery staple", &other, &salt, KdfParams::fast_for_tests()).unwrap();
        assert_ne!(k1.as_ref(), k4.as_ref());
    }

    #[test]
    fn canary_rejects_wrong_passphrase() {
        let (ak, salt, _) = mk();
        let params = KdfParams::fast_for_tests();

        // canary is minted with the good key
        let good = derive_master_key("correct horse battery staple", &ak, &salt, params).unwrap();
        let good_enc = expand_label(&good, HKDF_ENC).unwrap();
        let canary = make_canary(&good_enc).unwrap();
        assert!(check_canary(&good_enc, &canary).is_ok());

        // wrong passphrase → BadCredentials, not a vague decrypt error
        let wrong = derive_master_key("wrong", &ak, &salt, params).unwrap();
        let wrong_enc = expand_label(&wrong, HKDF_ENC).unwrap();
        assert!(matches!(check_canary(&wrong_enc, &canary), Err(Error::BadCredentials)));

        // right passphrase, wrong account key → also BadCredentials (indistinguishable on purpose)
        let other_ak = AccountKey::generate();
        let other = derive_master_key("correct horse battery staple", &other_ak, &salt, params).unwrap();
        let other_enc = expand_label(&other, HKDF_ENC).unwrap();
        assert!(matches!(check_canary(&other_enc, &canary), Err(Error::BadCredentials)));
    }

    #[test]
    fn aad_binds_ciphertext_to_slot() {
        let key = random_32();
        let ct = seal(&key, b"secret", b"ov|item-1").unwrap();
        assert_eq!(open(&key, &ct, b"ov|item-1").unwrap(), b"secret");
        // moving the ciphertext to another slot must fail
        assert!(open(&key, &ct, b"dt|item-1").is_err());
        assert!(open(&key, &ct, b"ov|item-2").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_32();
        let mut ct = seal(&key, b"secret", b"aad").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(open(&key, &ct, b"aad").is_err());
    }

    #[test]
    fn totp_matches_rfc6238_vector() {
        // RFC 6238 appendix B, SHA-1, secret "12345678901234567890", T = 59 s → 94287082
        // our digits are 6, so the RFC vector's last 6 digits must match.
        let secret = base32::encode(
            base32::Alphabet::Rfc4648 { padding: false },
            b"12345678901234567890",
        );
        let code = hotp(
            &base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &secret).unwrap(),
            59 / 30,
        )
        .unwrap();
        assert_eq!(&"94287082"[2..], code);
    }
}
