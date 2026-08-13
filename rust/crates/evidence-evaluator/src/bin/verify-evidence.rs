use agent_trust_evidence_evaluator::{EvidenceChainVerifier, EvidencePackage};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::VerifyingKey;
use std::{collections::BTreeMap, error::Error, fs};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        return Err(
            "usage: verify-evidence <package.json> <key-id> <base64url-ed25519-key>".into(),
        );
    }
    let package: EvidencePackage = serde_json::from_slice(&fs::read(&args[1])?)?;
    let raw_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&args[3])?
        .try_into()
        .map_err(|_| "Ed25519 verifying key must be exactly 32 bytes")?;
    let key = VerifyingKey::from_bytes(&raw_key)?;
    let report =
        EvidenceChainVerifier::new(BTreeMap::from([(args[2].clone(), key)])).verify(&package);
    println!("{}", serde_json::to_string_pretty(&report)?);
    if report.valid {
        Ok(())
    } else {
        Err("evidence verification failed".into())
    }
}
