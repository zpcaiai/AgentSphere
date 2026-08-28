//! Continuous, fail-closed production activation verification.
//!
//! The activation receipt is an authorization input, not startup configuration.  It is
//! therefore reopened and verified for every readiness probe and immediately before every
//! production operation.  A deployment watcher must replace the receipt atomically; this
//! module deliberately never caches a previously valid receipt as a long-lived truth.
//!
//! Watcher contract: create a dedicated-watcher-owned, reader-group `0440` temporary regular file
//! in the receipt's final
//! directory using `O_CREAT|O_EXCL|O_NOFOLLOW`, write exactly one complete
//! `agenttrust.production-closure-activation-receipt.v1` JSON document, `fsync` the file,
//! atomically rename it over the configured path, then `fsync` the parent directory.  Never
//! truncate or rewrite the live inode in place.  The parent directory chain must remain
//! root-owned and not group/world writable.

use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use agent_trust_production_closure::{
    ACTIVATION_RECEIPT_SCHEMA_VERSION, ProductionActivationReceipt,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
pub const MAX_ACTIVATION_STALENESS_SECONDS: u64 = 60;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    #[error("PRODUCTION_ACTIVATION_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("PRODUCTION_ACTIVATION_RECEIPT_UNAVAILABLE")]
    ReceiptUnavailable,
    #[error("PRODUCTION_ACTIVATION_RECEIPT_FILE_INVALID")]
    ReceiptFileInvalid,
    #[error("PRODUCTION_ACTIVATION_RECEIPT_INVALID")]
    ReceiptInvalid,
    #[error("PRODUCTION_ACTIVATION_RECEIPT_STALE")]
    ReceiptStale,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivationGuardianConfig {
    /// Immutable Git release identity of the bytes running this process.
    pub release_id: String,
    /// Watcher-owned, atomically replaced receipt.  This is intentionally not a static secret.
    pub receipt_path: PathBuf,
    /// Maximum age of `verified_at`; production constrains this to at most 60 seconds.
    pub max_staleness_seconds: u64,
    /// Dedicated watcher UID. The runtime UID must be different and cannot chmod the receipt.
    pub receipt_owner_uid: u32,
    /// Runtime's read-only group; the watcher uses this as its primary GID.
    pub receipt_reader_gid: u32,
}

impl ActivationGuardianConfig {
    pub fn validate(&self) -> Result<(), ActivationError> {
        if !is_release_id(&self.release_id)
            || !is_normalized_absolute_path(&self.receipt_path)
            || !(1..=MAX_ACTIVATION_STALENESS_SECONDS).contains(&self.max_staleness_seconds)
            || self.receipt_owner_uid == 0
            || self.receipt_reader_gid == 0
        {
            return Err(ActivationError::ConfigurationInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ActivationGuardian {
    config: ActivationGuardianConfig,
}

impl ActivationGuardian {
    pub fn new(config: ActivationGuardianConfig) -> Result<Self, ActivationError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &ActivationGuardianConfig {
        &self.config
    }

    /// Reopen and verify the current receipt.  No successful result is retained by the guard.
    pub fn require_active(&self) -> Result<ProductionActivationReceipt, ActivationError> {
        self.require_active_at(Utc::now())
    }

    fn require_active_at(
        &self,
        checked_at: DateTime<Utc>,
    ) -> Result<ProductionActivationReceipt, ActivationError> {
        let bytes = read_protected_receipt(
            &self.config.receipt_path,
            self.config.receipt_owner_uid,
            self.config.receipt_reader_gid,
        )?;
        verify_receipt_bytes(&bytes, &self.config, checked_at)
    }
}

fn verify_receipt_bytes(
    bytes: &[u8],
    config: &ActivationGuardianConfig,
    checked_at: DateTime<Utc>,
) -> Result<ProductionActivationReceipt, ActivationError> {
    let value = parse_strict_json(
        bytes,
        &ParseLimits {
            max_body_bytes: MAX_RECEIPT_BYTES as usize,
            max_depth: 8,
            max_array_items: 0,
            max_string_bytes: 1_024,
            max_object_keys: 32,
            max_number_chars: 32,
        },
    )
    .map_err(|_| ActivationError::ReceiptInvalid)?;
    let receipt: ProductionActivationReceipt =
        serde_json::from_value(value).map_err(|_| ActivationError::ReceiptInvalid)?;
    if receipt.schema_version != ACTIVATION_RECEIPT_SCHEMA_VERSION
        || receipt.release_id != config.release_id
        || !receipt.production_write_enabled
        || !receipt_shape_valid(&receipt)
        || receipt.verify_digest().is_err()
        || receipt.verified_at > checked_at
        || receipt.valid_until <= checked_at
    {
        return Err(ActivationError::ReceiptInvalid);
    }
    let age = checked_at.signed_duration_since(receipt.verified_at);
    let maximum = Duration::seconds(config.max_staleness_seconds as i64);
    if age < Duration::zero() || age > maximum {
        return Err(ActivationError::ReceiptStale);
    }
    Ok(receipt)
}

fn receipt_shape_valid(receipt: &ProductionActivationReceipt) -> bool {
    receipt.certificate_id.len() == 27
        && receipt.certificate_id.starts_with("pc-")
        && is_lower_hex(&receipt.certificate_id[3..], 24)
        && is_release_id(&receipt.release_id)
        && [
            &receipt.scope_digest,
            &receipt.input_digest,
            &receipt.report_digest,
            &receipt.activation_expectation_digest,
            &receipt.revocation_registry_digest,
            &receipt.receipt_digest,
        ]
        .into_iter()
        .all(|value| is_lower_hex(value, 64))
        && receipt.revocation_sequence > 0
        && !receipt.revocation_registry_id.is_empty()
        && receipt.revocation_registry_id.len() <= 256
        && receipt
            .revocation_registry_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| {
                byte.is_ascii_alphanumeric()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
            })
}

fn is_release_id(value: &str) -> bool {
    value
        .strip_prefix("git:sha1:")
        .is_some_and(|digest| is_lower_hex(digest, 40))
        || value
            .strip_prefix("git:sha256:")
            .is_some_and(|digest| is_lower_hex(digest, 64))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_normalized_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(unix)]
fn read_protected_receipt(
    path: &Path,
    expected_owner_uid: u32,
    expected_reader_gid: u32,
) -> Result<Vec<u8>, ActivationError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if !is_normalized_absolute_path(path) {
        return Err(ActivationError::ReceiptFileInvalid);
    }
    // The final directory is owned by the dedicated watcher and mounted read-only into the
    // runtime. Every earlier directory remains root-owned and non-writable to the runtime.
    for (index, parent) in path
        .parent()
        .ok_or(ActivationError::ReceiptFileInvalid)?
        .ancestors()
        .enumerate()
    {
        let metadata =
            std::fs::symlink_metadata(parent).map_err(|_| ActivationError::ReceiptUnavailable)?;
        let mode = metadata.permissions().mode() & 0o7777;
        let owner_valid = if index == 0 {
            metadata.uid() == expected_owner_uid
                && metadata.gid() == expected_reader_gid
                && mode == 0o750
        } else {
            metadata.uid() == 0 && mode & 0o022 == 0
        };
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || !owner_valid
        {
            return Err(ActivationError::ReceiptFileInvalid);
        }
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ActivationError::ReceiptUnavailable)?;
    let before = file
        .metadata()
        .map_err(|_| ActivationError::ReceiptUnavailable)?;
    let mode = before.permissions().mode() & 0o7777;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.uid() != expected_owner_uid
        || before.gid() != expected_reader_gid
        || before.nlink() != 1
        || mode != 0o440
        || before.len() == 0
        || before.len() > MAX_RECEIPT_BYTES
    {
        return Err(ActivationError::ReceiptFileInvalid);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ActivationError::ReceiptUnavailable)?;
    let after = file
        .metadata()
        .map_err(|_| ActivationError::ReceiptUnavailable)?;
    if bytes.len() as u64 != before.len()
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || after.len() != before.len()
        || after.mtime() != before.mtime()
        || after.mtime_nsec() != before.mtime_nsec()
    {
        return Err(ActivationError::ReceiptFileInvalid);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_protected_receipt(_: &Path, _: u32, _: u32) -> Result<Vec<u8>, ActivationError> {
    // The production runtime is Linux-only; other platforms cannot assert the ownership and
    // no-follow properties required for activation authorization.
    Err(ActivationError::ReceiptFileInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn config() -> ActivationGuardianConfig {
        ActivationGuardianConfig {
            release_id: format!("git:sha256:{}", "a".repeat(64)),
            receipt_path: PathBuf::from("/run/agenttrust/production-activation-receipt.json"),
            max_staleness_seconds: 30,
            receipt_owner_uid: 65531,
            receipt_reader_gid: 65532,
        }
    }

    fn receipt(now: DateTime<Utc>) -> ProductionActivationReceipt {
        let mut receipt = ProductionActivationReceipt {
            schema_version: ACTIVATION_RECEIPT_SCHEMA_VERSION.into(),
            certificate_id: format!("pc-{}", "b".repeat(24)),
            release_id: config().release_id,
            scope_digest: "c".repeat(64),
            input_digest: "d".repeat(64),
            report_digest: "e".repeat(64),
            activation_expectation_digest: "f".repeat(64),
            revocation_registry_id: "production-registry".into(),
            revocation_sequence: 7,
            revocation_registry_digest: "1".repeat(64),
            verified_at: now - Duration::seconds(5),
            valid_until: now + Duration::minutes(5),
            production_write_enabled: true,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = format!(
            "{:x}",
            Sha256::digest(
                serde_jcs::to_vec(&receipt).unwrap_or_else(|_| panic!("serialize receipt"))
            )
        );
        receipt
    }

    fn bytes(receipt: &ProductionActivationReceipt) -> Vec<u8> {
        serde_json::to_vec(receipt).unwrap_or_else(|_| panic!("serialize receipt"))
    }

    #[test]
    fn exact_fresh_release_bound_receipt_passes() {
        let now = Utc::now();
        assert!(verify_receipt_bytes(&bytes(&receipt(now)), &config(), now).is_ok());
    }

    #[test]
    fn stale_future_expired_wrong_release_and_disabled_receipts_fail_closed() {
        let now = Utc::now();
        let mut stale = receipt(now);
        stale.verified_at = now - Duration::seconds(31);
        stale.receipt_digest.clear();
        stale.receipt_digest = format!(
            "{:x}",
            Sha256::digest(
                serde_jcs::to_vec(&stale).unwrap_or_else(|_| panic!("serialize receipt"))
            )
        );
        assert_eq!(
            verify_receipt_bytes(&bytes(&stale), &config(), now),
            Err(ActivationError::ReceiptStale)
        );

        for mutation in ["future", "expired", "release", "disabled", "digest"] {
            let mut invalid = receipt(now);
            match mutation {
                "future" => invalid.verified_at = now + Duration::seconds(1),
                "expired" => invalid.valid_until = now,
                "release" => invalid.release_id = format!("git:sha256:{}", "9".repeat(64)),
                "disabled" => invalid.production_write_enabled = false,
                "digest" => invalid.scope_digest = "8".repeat(64),
                _ => unreachable!(),
            }
            if mutation != "digest" {
                invalid.receipt_digest.clear();
                invalid.receipt_digest = format!(
                    "{:x}",
                    Sha256::digest(
                        serde_jcs::to_vec(&invalid).unwrap_or_else(|_| panic!("serialize receipt"))
                    )
                );
            }
            assert!(verify_receipt_bytes(&bytes(&invalid), &config(), now).is_err());
        }
    }

    #[test]
    fn duplicate_json_partial_json_and_oversized_staleness_are_rejected() {
        let now = Utc::now();
        let valid = String::from_utf8(bytes(&receipt(now)))
            .unwrap_or_else(|_| panic!("receipt must be UTF-8"));
        let duplicate = valid.replacen(
            "{",
            &format!("{{\"release_id\":\"{}\",", config().release_id),
            1,
        );
        assert_eq!(
            verify_receipt_bytes(duplicate.as_bytes(), &config(), now),
            Err(ActivationError::ReceiptInvalid)
        );
        assert_eq!(
            verify_receipt_bytes(&bytes(&receipt(now))[..24], &config(), now),
            Err(ActivationError::ReceiptInvalid)
        );
        let mut invalid_config = config();
        invalid_config.max_staleness_seconds = 61;
        assert_eq!(
            invalid_config.validate(),
            Err(ActivationError::ConfigurationInvalid)
        );
    }
}
