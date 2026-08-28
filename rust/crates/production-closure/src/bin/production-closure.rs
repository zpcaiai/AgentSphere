#[cfg(feature = "development-local-signing")]
use agent_trust_production_closure::ClosureAuthority;
use agent_trust_production_closure::{
    ClosureInput, ClosureReport, ClosureRunner, ClosureScope, DomainAssuranceAttestation,
    ExternalCertificateSignature, ExternalCertificateSigningRequest,
    ExternalGateAssuranceAttestation, ProductionClosureCertificate,
    SignedCertificateRevocationRegistry,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
#[cfg(feature = "development-local-signing")]
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const MAXIMUM_INPUT_BYTES: u64 = 128 * 1024 * 1024;

#[cfg(feature = "development-local-signing")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeySpec {
    schema_version: String,
    key_id: String,
    private_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeySpec {
    schema_version: String,
    key_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssurancePublicKeySetSpec {
    schema_version: String,
    keys: Vec<PublicKeySpec>,
}

fn read_json<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T, &'static str> {
    let metadata = fs::metadata(path).map_err(|_| "CLOSURE_INPUT_UNREADABLE")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err("CLOSURE_INPUT_SIZE_INVALID");
    }
    let bytes = fs::read(path).map_err(|_| "CLOSURE_INPUT_UNREADABLE")?;
    serde_json::from_slice(&bytes).map_err(|_| "CLOSURE_INPUT_INVALID")
}

fn write_new<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "CLOSURE_OUTPUT_INVALID")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "CLOSURE_OUTPUT_ALREADY_EXISTS_OR_UNWRITABLE")?;
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|_| "CLOSURE_OUTPUT_WRITE_FAILED")
}

fn decode_32(value: &str) -> Result<[u8; 32], &'static str> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| "CLOSURE_KEY_INVALID")?
        .try_into()
        .map_err(|_| "CLOSURE_KEY_INVALID")
}

#[cfg(all(unix, feature = "development-local-signing"))]
fn require_private_permissions(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|_| "CLOSURE_KEY_UNREADABLE")?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err("CLOSURE_PRIVATE_KEY_PERMISSIONS_TOO_OPEN");
    }
    Ok(())
}

#[cfg(all(not(unix), feature = "development-local-signing"))]
fn require_private_permissions(_: &Path) -> Result<(), &'static str> {
    Err("CLOSURE_PRIVATE_KEY_PERMISSION_CHECK_UNSUPPORTED")
}

#[cfg(feature = "development-local-signing")]
fn require_development_local_signing() -> Result<(), &'static str> {
    if env::var("AGENT_TRUST_PROFILE").as_deref() != Ok("development")
        || env::var("AGENT_TRUST_ALLOW_LOCAL_CLOSURE_SIGNING").as_deref()
            != Ok("I_UNDERSTAND_LOCAL_KEYS_ARE_NOT_PRODUCTION")
    {
        return Err("CLOSURE_LOCAL_SIGNING_DISABLED");
    }
    Ok(())
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("evaluate") => {
            let input: ClosureInput = read_json(
                Path::new(&args.next().ok_or("CLOSURE_INPUT_REQUIRED")?),
                MAXIMUM_INPUT_BYTES,
            )?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let report = ClosureRunner::evaluate(&input, Utc::now())
                .map_err(|_| "CLOSURE_EVALUATION_FAILED")?;
            write_new(Path::new(&output), &report)?;
            println!(
                "{}",
                json!({"eligible":report.eligible,"report_digest":report.report_digest,"blocker_count":report.blockers.len()})
            );
        }
        Some("issue") => return Err("CLOSURE_EXTERNAL_SIGNING_REQUIRED"),
        #[cfg(feature = "development-local-signing")]
        Some("issue-local") => {
            require_development_local_signing()?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let scope_path = args.next().ok_or("CLOSURE_SCOPE_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let scope: ClosureScope = read_json(Path::new(&scope_path), MAXIMUM_INPUT_BYTES)?;
            require_private_permissions(Path::new(&key_path))?;
            let spec: SigningKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-signing-key.v1" || spec.key_id.is_empty()
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let authority = ClosureAuthority::new(
                spec.key_id,
                SigningKey::from_bytes(&decode_32(&spec.private_key)?),
            )
            .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let certificate = authority
                .issue(&report, &scope, Utc::now())
                .map_err(|_| "CLOSURE_CERTIFICATE_NOT_ELIGIBLE")?;
            write_new(Path::new(&output), &certificate)?;
            println!(
                "{}",
                json!({"certificate_id":certificate.certificate_id,"issued":true,"production_signing":false})
            );
        }
        Some("prepare-external-signing") => {
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let scope_path = args.next().ok_or("CLOSURE_SCOPE_REQUIRED")?;
            let key_id = args.next().ok_or("CLOSURE_KEY_ID_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() || !valid_key_id(&key_id) {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let scope: ClosureScope = read_json(Path::new(&scope_path), MAXIMUM_INPUT_BYTES)?;
            let request =
                ExternalCertificateSigningRequest::prepare(&report, &scope, key_id, Utc::now())
                    .map_err(|_| "CLOSURE_CERTIFICATE_NOT_ELIGIBLE")?;
            let request_digest = request
                .digest()
                .map_err(|_| "CLOSURE_SIGNING_REQUEST_INVALID")?;
            write_new(Path::new(&output), &request)?;
            println!(
                "{}",
                json!({"request_digest":request_digest,"prepared":true,"private_key_loaded":false})
            );
        }
        Some("finalize-external-signing") => {
            let request_path = args.next().ok_or("CLOSURE_SIGNING_REQUEST_REQUIRED")?;
            let signature_path = args.next().ok_or("CLOSURE_EXTERNAL_SIGNATURE_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let scope_path = args.next().ok_or("CLOSURE_SCOPE_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let request: ExternalCertificateSigningRequest =
                read_json(Path::new(&request_path), MAXIMUM_INPUT_BYTES)?;
            let signature: ExternalCertificateSignature =
                read_json(Path::new(&signature_path), 64 * 1024)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let scope: ClosureScope = read_json(Path::new(&scope_path), MAXIMUM_INPUT_BYTES)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != request.key_id
                || spec.key_id != signature.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let certificate = signature
                .finalize(&request, &report, &scope, &key, Utc::now())
                .map_err(|_| "CLOSURE_EXTERNAL_SIGNING_INVALID")?;
            write_new(Path::new(&output), &certificate)?;
            println!(
                "{}",
                json!({"certificate_id":certificate.certificate_id,"issued":true,"production_signing":true,"verified":true})
            );
        }
        Some("verify") => {
            let certificate_path = args.next().ok_or("CLOSURE_CERTIFICATE_REQUIRED")?;
            let report_path = args.next().ok_or("CLOSURE_REPORT_REQUIRED")?;
            let key_path = args.next().ok_or("CLOSURE_KEY_REQUIRED")?;
            let registry_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let registry_key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let certificate: ProductionClosureCertificate =
                read_json(Path::new(&certificate_path), MAXIMUM_INPUT_BYTES)?;
            let report: ClosureReport = read_json(Path::new(&report_path), MAXIMUM_INPUT_BYTES)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            let registry: SignedCertificateRevocationRegistry =
                read_json(Path::new(&registry_path), 32 * 1024 * 1024)?;
            let registry_key_spec: PublicKeySpec =
                read_json(Path::new(&registry_key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != certificate.key_id
                || registry_key_spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || registry_key_spec.key_id != registry.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            let registry_key = VerifyingKey::from_bytes(&decode_32(&registry_key_spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            registry
                .verify_active(&certificate, &report, &key, &registry_key, Utc::now())
                .map_err(|_| "CLOSURE_CERTIFICATE_INVALID")?;
            println!(
                "{}",
                json!({"certificate_id":certificate.certificate_id,"verified":true,"revocation_registry_id":registry.registry_id,"revocation_sequence":registry.sequence,"revocation_registry_digest":registry.digest().map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?})
            );
        }
        Some("verify-revocation-registry") => {
            let registry_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let registry: SignedCertificateRevocationRegistry =
                read_json(Path::new(&registry_path), 32 * 1024 * 1024)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != registry.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            registry
                .verify(&key, Utc::now())
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            println!(
                "{}",
                json!({"registry_id":registry.registry_id,"sequence":registry.sequence,"verified":true,"registry_digest":registry.digest().map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?})
            );
        }
        Some("verify-revocation-successor") => {
            let previous_path = args
                .next()
                .ok_or("CLOSURE_PREVIOUS_REVOCATION_REGISTRY_REQUIRED")?;
            let current_path = args.next().ok_or("CLOSURE_REVOCATION_REGISTRY_REQUIRED")?;
            let key_path = args
                .next()
                .ok_or("CLOSURE_REVOCATION_REGISTRY_KEY_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let previous: SignedCertificateRevocationRegistry =
                read_json(Path::new(&previous_path), 32 * 1024 * 1024)?;
            let current: SignedCertificateRevocationRegistry =
                read_json(Path::new(&current_path), 32 * 1024 * 1024)?;
            let spec: PublicKeySpec = read_json(Path::new(&key_path), 64 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key.v1"
                || spec.key_id != previous.key_id
                || spec.key_id != current.key_id
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let key = VerifyingKey::from_bytes(&decode_32(&spec.public_key)?)
                .map_err(|_| "CLOSURE_KEY_INVALID")?;
            current
                .verify_successor(&previous, &key, Utc::now())
                .map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?;
            println!(
                "{}",
                json!({"registry_id":current.registry_id,"previous_sequence":previous.sequence,"sequence":current.sequence,"verified_successor":true,"registry_digest":current.digest().map_err(|_| "CLOSURE_REVOCATION_REGISTRY_INVALID")?})
            );
        }
        Some("verify-domain-assurance") => {
            let attestation_path = args.next().ok_or("CLOSURE_ATTESTATION_REQUIRED")?;
            let key_set_path = args.next().ok_or("CLOSURE_KEY_SET_REQUIRED")?;
            let expected_scope_digest = args.next().ok_or("CLOSURE_SCOPE_DIGEST_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let attestation: DomainAssuranceAttestation =
                read_json(Path::new(&attestation_path), MAXIMUM_INPUT_BYTES)?;
            let spec: AssurancePublicKeySetSpec = read_json(Path::new(&key_set_path), 1024 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key-set.v1"
                || spec.keys.len() < 2
                || spec.keys.len() > 100
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let mut keys = BTreeMap::new();
            for item in spec.keys {
                if item.schema_version != "agenttrust.ed25519-public-key.v1"
                    || item.key_id.is_empty()
                    || keys
                        .insert(
                            item.key_id,
                            VerifyingKey::from_bytes(&decode_32(&item.public_key)?)
                                .map_err(|_| "CLOSURE_KEY_INVALID")?,
                        )
                        .is_some()
                {
                    return Err("CLOSURE_KEY_INVALID");
                }
            }
            attestation
                .verify_offline(&expected_scope_digest, &keys, Utc::now())
                .map_err(|_| "CLOSURE_DOMAIN_ASSURANCE_INVALID")?;
            println!(
                "{}",
                json!({"attestation_id":attestation.attestation_id,"verified":true,"attestation_digest":attestation.digest().map_err(|_| "CLOSURE_DOMAIN_ASSURANCE_INVALID")?})
            );
        }
        Some("verify-external-assurance") => {
            let attestation_path = args.next().ok_or("CLOSURE_ATTESTATION_REQUIRED")?;
            let key_set_path = args.next().ok_or("CLOSURE_KEY_SET_REQUIRED")?;
            let expected_scope_digest = args.next().ok_or("CLOSURE_SCOPE_DIGEST_REQUIRED")?;
            let output = args.next().ok_or("CLOSURE_OUTPUT_REQUIRED")?;
            if args.next().is_some() {
                return Err("CLOSURE_ARGUMENTS_INVALID");
            }
            let attestation: ExternalGateAssuranceAttestation =
                read_json(Path::new(&attestation_path), MAXIMUM_INPUT_BYTES)?;
            let spec: AssurancePublicKeySetSpec = read_json(Path::new(&key_set_path), 1024 * 1024)?;
            if spec.schema_version != "agenttrust.ed25519-public-key-set.v1"
                || spec.keys.len() < 2
                || spec.keys.len() > 100
            {
                return Err("CLOSURE_KEY_INVALID");
            }
            let mut keys = BTreeMap::new();
            for item in spec.keys {
                if item.schema_version != "agenttrust.ed25519-public-key.v1"
                    || item.key_id.is_empty()
                    || keys
                        .insert(
                            item.key_id,
                            VerifyingKey::from_bytes(&decode_32(&item.public_key)?)
                                .map_err(|_| "CLOSURE_KEY_INVALID")?,
                        )
                        .is_some()
                {
                    return Err("CLOSURE_KEY_INVALID");
                }
            }
            let evidence = attestation
                .verified_gate_evidence(&expected_scope_digest, &keys, Utc::now())
                .map_err(|_| "CLOSURE_EXTERNAL_ASSURANCE_INVALID")?;
            write_new(Path::new(&output), &evidence)?;
            println!(
                "{}",
                json!({"attestation_id":attestation.attestation_id,"gate_id":attestation.gate_id,"verified":true,"attestation_digest":attestation.digest().map_err(|_| "CLOSURE_EXTERNAL_ASSURANCE_INVALID")?})
            );
        }
        _ => {
            return Err(
                "USAGE: production-closure evaluate|prepare-external-signing|finalize-external-signing|issue-local|verify|verify-revocation-registry|verify-revocation-successor|verify-domain-assurance|verify-external-assurance ...",
            );
        }
    }
    Ok(())
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
