use agent_trust_enterprise_approval::{
    ApprovalPrincipalAssertionKeyring, ApprovalReviewEvidenceKeyring,
};
use agent_trust_enterprise_approval::evidence_delivery::ApprovalEvidencePublisher;
use agent_trust_enterprise_approval::postgres::{
    ApprovalDecisionEvidenceKeyring, ApprovalSigner, PostgresApprovalStore,
};
use agent_trust_enterprise_approval::server::{
    ApprovalApiState, ApprovalServerConfig, TokenBindingApprovalAuthorizer, serve,
    validate_certificate_identity_file,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::BTreeSet;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    data: SocketAddr,
    management: SocketAddr,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_args(env::args().skip(1))?;
    let database_url = read_secret("AGENT_TRUST_APPROVAL_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_APPROVAL_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_APPROVAL_DATABASE_CA_FILE", false)?;
    let expected_role = required_database_role("AGENT_TRUST_APPROVAL_DATABASE_EXPECTED_ROLE")?;
    let connect = validate_database_url(&database_url, &database_ca, &expected_role)?
        .password(&database_password);
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_with(connect)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;

    let signer = ApprovalSigner::new(
        required_identifier("AGENT_TRUST_APPROVAL_ISSUER")?,
        required_key_identifier("AGENT_TRUST_APPROVAL_KEY_ID")?,
        read_signing_key("AGENT_TRUST_APPROVAL_PRIVATE_KEY_FILE")?,
    )?;
    let review_evidence_keyring = ApprovalReviewEvidenceKeyring::from_file(&required_file(
        "AGENT_TRUST_APPROVAL_REVIEW_EVIDENCE_KEYRING_FILE",
        false,
    )?)?;
    let decision_evidence_keyring = ApprovalDecisionEvidenceKeyring::from_file(&required_file(
        "AGENT_TRUST_APPROVAL_DECISION_EVIDENCE_KEYRING_FILE",
        false,
    )?)?;
    let delivery_evidence_keyring = ApprovalReviewEvidenceKeyring::from_file(&required_file(
        "AGENT_TRUST_APPROVAL_EVIDENCE_RECEIPT_KEYRING_FILE",
        false,
    )?)?;
    let evidence_source_identity = required_env("AGENT_TRUST_APPROVAL_EVIDENCE_SOURCE_IDENTITY")?;
    let evidence_client_certificate = required_file(
        "AGENT_TRUST_APPROVAL_EVIDENCE_CLIENT_CERTIFICATE_FILE",
        false,
    )?;
    validate_certificate_identity_file(
        &evidence_client_certificate,
        &evidence_source_identity,
    )?;
    let evidence_publisher = Arc::new(ApprovalEvidencePublisher::new(
        url::Url::parse(&required_env("AGENT_TRUST_APPROVAL_EVIDENCE_ENDPOINT")?)?,
        required_file("AGENT_TRUST_APPROVAL_EVIDENCE_TOKEN_FILE", true)?,
        &required_file("AGENT_TRUST_APPROVAL_EVIDENCE_CA_FILE", false)?,
        &evidence_client_certificate,
        &required_file(
            "AGENT_TRUST_APPROVAL_EVIDENCE_CLIENT_PRIVATE_KEY_FILE",
            true,
        )?,
        required_env("AGENT_TRUST_APPROVAL_EVIDENCE_READINESS_SCHEMA")?,
        delivery_evidence_keyring.clone(),
    )?);
    let store = Arc::new(PostgresApprovalStore::new(
        pool,
        signer,
        review_evidence_keyring,
        delivery_evidence_keyring,
        decision_evidence_keyring,
        evidence_source_identity,
        evidence_publisher,
    )?);
    if !store.ready().await {
        return Err("APPROVAL_DATABASE_NOT_READY".into());
    }
    let identities = parse_identities(&required_env("AGENT_TRUST_APPROVAL_CLIENT_IDENTITIES")?)?;
    let bindings_file = required_file("AGENT_TRUST_APPROVAL_TOKEN_BINDINGS_FILE", true)?;
    let authorizer = Arc::new(TokenBindingApprovalAuthorizer::from_file(
        &bindings_file,
        &identities,
    )?);
    if authorizer.tenants().is_empty() {
        return Err("APPROVAL_TENANT_BINDINGS_REQUIRED".into());
    }
    let delivery_tenants = authorizer.tenants().clone();
    let principal_keyring = Arc::new(ApprovalPrincipalAssertionKeyring::from_file(
        &required_file("AGENT_TRUST_APPROVAL_PRINCIPAL_KEYS_FILE", false)?,
        &required_audience("AGENT_TRUST_APPROVAL_PRINCIPAL_AUDIENCE")?,
    )?);
    let state = ApprovalApiState::production(store.clone(), authorizer, principal_keyring)?;
    let server = serve(
        ApprovalServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_APPROVAL_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file(
                "AGENT_TRUST_APPROVAL_TLS_CERTIFICATE_FILE",
                false,
            )?,
            tls_private_key_file: required_file("AGENT_TRUST_APPROVAL_TLS_PRIVATE_KEY_FILE", true)?,
            client_identities: identities,
        },
        state,
    );
    let delivery = store.run_decision_evidence_delivery(
        delivery_tenants,
        uuid::Uuid::new_v4().to_string(),
    );
    tokio::select! {
        result = server => result?,
        result = delivery => {
            result?;
            return Err("APPROVAL_EVIDENCE_DELIVERY_STOPPED".into());
        }
    }
    Ok(())
}

fn validate_database_url(
    value: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let query = parsed.query_pairs().collect::<Vec<_>>();
    let mut normalized = std::collections::BTreeMap::new();
    for (key, value) in &query {
        let key = key.to_ascii_lowercase();
        if value.is_empty() || normalized.insert(key, value.as_ref()).is_some() {
            return Err("APPROVAL_DATABASE_URL_INVALID".into());
        }
    }
    let forbidden_tls = normalized
        .keys()
        .any(|key| key.starts_with("ssl") && key != "sslmode");
    let database_name = parsed.path().strip_prefix('/').filter(|value| {
        !value.is_empty()
            && value.len() <= 128
            && !value.contains('/')
            && value.bytes().all(|byte| byte.is_ascii_graphic())
    });
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || database_name.is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || normalized.get("sslmode") != Some(&"verify-full")
        || normalized.get("options") != Some(&"-csearch_path=pg_catalog,public")
        || forbidden_tls
        || !ca_file.is_absolute()
    {
        return Err("APPROVAL_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::from_str(value)?
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file))
}

async fn verify_database_posture(
    pool: &sqlx::PgPool,
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
                current_setting('search_path') AS search_path,\
                current_schemas(false)::text AS resolved_schemas,\
                current_setting('row_security') AS row_security,\
                has_schema_privilege(current_user,'public','CREATE') AS can_create,\
                has_table_privilege(current_user,'public.approval_cases','DELETE') AS can_delete_cases,\
                has_table_privilege(current_user,'public.approval_consumptions','DELETE') AS can_delete_receipts,\
                has_column_privilege(current_user,'public.approval_grants','signed_grant','UPDATE') AS can_replace_grant,\
                has_column_privilege(current_user,'public.approval_grants','remaining_uses','UPDATE') AS can_consume_grant,\
                has_table_privilege(current_user,'public.approval_decision_evidence_receipts','DELETE') AS can_delete_decision_evidence,\
                has_column_privilege(current_user,'public.approval_decision_evidence_receipts','signed_receipt','UPDATE') AS can_replace_decision_evidence,\
                has_table_privilege(current_user,'public.approval_decision_evidence_outbox','DELETE') AS can_delete_decision_outbox,\
                has_column_privilege(current_user,'public.approval_decision_evidence_outbox','authority_request','UPDATE') AS can_replace_decision_outbox,\
                (has_column_privilege(current_user,'public.approval_decision_evidence_outbox','delivery_attempts','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','next_attempt_at','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','lease_owner','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','lease_expires_at','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','last_attempt_at','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','last_error_code','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','signed_authority_receipt','UPDATE')\
                 AND has_column_privilege(current_user,'public.approval_decision_evidence_outbox','delivered_at','UPDATE'))\
                   AS can_deliver_decision_outbox \
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
    if row.try_get::<String, _>("role_name")? != expected_role
        || row.try_get::<bool, _>("rolsuper")?
        || row.try_get::<bool, _>("rolbypassrls")?
        || row.try_get::<bool, _>("rolcreatedb")?
        || row.try_get::<bool, _>("rolcreaterole")?
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_delete_cases")?
        || row.try_get::<bool, _>("can_delete_receipts")?
        || row.try_get::<bool, _>("can_replace_grant")?
        || row.try_get::<bool, _>("can_delete_decision_evidence")?
        || row.try_get::<bool, _>("can_replace_decision_evidence")?
        || row.try_get::<bool, _>("can_delete_decision_outbox")?
        || row.try_get::<bool, _>("can_replace_decision_outbox")?
        || !row.try_get::<bool, _>("can_consume_grant")?
        || !row.try_get::<bool, _>("can_deliver_decision_outbox")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("APPROVAL_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8085_u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9095_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("APPROVAL_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("APPROVAL_ARGUMENTS_INVALID".into()),
        }
    }
    if port == 0 || management_port == 0 || port == management_port {
        return Err("APPROVAL_ARGUMENTS_INVALID".into());
    }
    let data = format!("{listen}:{port}").parse::<SocketAddr>()?;
    let management = format!("{management_listen}:{management_port}").parse::<SocketAddr>()?;
    if !management.ip().is_unspecified() && !management.ip().is_loopback() {
        return Err("APPROVAL_MANAGEMENT_LISTENER_MUST_BE_LOOPBACK_OR_UNSPECIFIED".into());
    }
    Ok(Arguments { data, management })
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name}_REQUIRED").into())
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_audience(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.trim().is_empty()
        || value.len() > 256
        || value.contains('\0')
        || value.contains(['\r', '\n'])
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_database_role(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.len() > 63
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_key_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_file(name: &str, secret: bool) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute() || !secure_file(&path, secret)? {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(path)
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let access = if private {
        let allowed_bits = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
        let readable = (metadata.uid() == uid && mode & 0o400 != 0)
            || (metadata.gid() == gid && mode & 0o040 != 0);
        readable && mode & !allowed_bits == 0
    } else {
        mode & 0o022 == 0
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() > 0
        && metadata.len() <= 1_048_576
        && access)
}

#[cfg(not(unix))]
fn secure_file(path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1_048_576)
}

fn read_secret(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    let bytes = std::fs::read(path)?;
    if bytes.is_empty() || bytes.len() > 16_384 || bytes.contains(&0) {
        return Err(format!("{name}_INVALID").into());
    }
    let raw = std::str::from_utf8(&bytes)?;
    let value = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(raw);
    if value.is_empty() || value.contains(['\r', '\n']) {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value.into())
}

fn read_signing_key(name: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    let raw = std::fs::read(path)?;
    if raw.is_empty() || raw.len() > 256 {
        return Err(format!("{name}_INVALID").into());
    }
    let bytes = if raw.len() == 32 {
        raw
    } else {
        let raw = std::str::from_utf8(&raw)?;
        let encoded = raw
            .strip_suffix("\r\n")
            .or_else(|| raw.strip_suffix('\n'))
            .unwrap_or(raw);
        if encoded.contains(['\r', '\n']) {
            return Err(format!("{name}_INVALID").into());
        }
        URL_SAFE_NO_PAD.decode(encoded)?
    };
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{name}_MUST_BE_32_BYTES"))?;
    Ok(SigningKey::from_bytes(&key))
}

fn parse_identities(value: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let identities = value
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err("APPROVAL_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_listener_is_loopback_or_unspecified_only() {
        let unspecified = parse_args(["--management-listen".into(), "0.0.0.0".into()]);
        assert!(unspecified.is_ok());
        let routed = parse_args(["--management-listen".into(), "10.0.0.8".into()]);
        assert!(routed.is_err());
    }

    #[test]
    fn database_url_cannot_carry_a_password() {
        let value = "postgresql://agenttrust_approval_runtime:secret@db.internal/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic";
        assert!(
            validate_database_url(
                value,
                Path::new("/run/secrets/db-ca.pem"),
                "agenttrust_approval_runtime",
            )
            .is_err()
        );
    }
}
