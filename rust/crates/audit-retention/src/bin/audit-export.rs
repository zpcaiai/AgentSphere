use agent_trust_audit_retention::{AuditExportPackage, IntegrityVerifier};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::Path;

const MAXIMUM_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_KEYRING_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRing {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::metadata(path).map_err(|_| "AUDIT_EXPORT_INPUT_UNREADABLE")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err("AUDIT_EXPORT_INPUT_SIZE_INVALID");
    }
    fs::read(path).map_err(|_| "AUDIT_EXPORT_INPUT_UNREADABLE")
}

fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() != Some("verify") {
        return Err("USAGE: audit-export verify PACKAGE_JSON PUBLIC_KEYRING_JSON");
    }
    let package_path = args.next().ok_or("AUDIT_EXPORT_PACKAGE_REQUIRED")?;
    let keyring_path = args.next().ok_or("AUDIT_EXPORT_KEYRING_REQUIRED")?;
    if args.next().is_some() {
        return Err("AUDIT_EXPORT_ARGUMENTS_INVALID");
    }
    let package: AuditExportPackage = serde_json::from_slice(&bounded_read(
        Path::new(&package_path),
        MAXIMUM_PACKAGE_BYTES,
    )?)
    .map_err(|_| "AUDIT_EXPORT_PACKAGE_INVALID")?;
    let ring: PublicKeyRing = serde_json::from_slice(&bounded_read(
        Path::new(&keyring_path),
        MAXIMUM_KEYRING_BYTES,
    )?)
    .map_err(|_| "AUDIT_EXPORT_KEYRING_INVALID")?;
    if ring.schema_version != "agenttrust.ed25519-public-keyring.v1"
        || ring.keys.is_empty()
        || ring.keys.len() > 1024
    {
        return Err("AUDIT_EXPORT_KEYRING_INVALID");
    }
    let mut keys = BTreeMap::new();
    for (key_id, encoded) in ring.keys {
        if key_id.is_empty() || key_id.len() > 256 {
            return Err("AUDIT_EXPORT_KEYRING_INVALID");
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "AUDIT_EXPORT_KEYRING_INVALID")?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "AUDIT_EXPORT_KEYRING_INVALID")?;
        let key = VerifyingKey::from_bytes(&array).map_err(|_| "AUDIT_EXPORT_KEYRING_INVALID")?;
        keys.insert(key_id, key);
    }
    IntegrityVerifier::new(keys)
        .verify(&package)
        .map_err(|_| "AUDIT_EXPORT_INTEGRITY_FAILED")?;
    let result = json!({
        "schema_version": "agenttrust.audit-export-verification.v1",
        "export_id": package.manifest.export_id,
        "tenant_id": package.manifest.tenant_id,
        "manifest_hash": package.manifest.manifest_hash,
        "chain_head": package.manifest.chain_head,
        "record_count": package.records.len(),
        "verified": true
    });
    println!("{result}");
    Ok(())
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
