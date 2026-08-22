use agent_trust_evidence_evaluator::artifact::HttpWormArtifactStore;
use agent_trust_evidence_evaluator::postgres::PostgresEvidenceStore;
use agent_trust_evidence_evaluator::server::{
    EvidenceServerConfig, TokenBindingEvidenceAuthorizer, serve,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    data: SocketAddr,
    management: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRing {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("EVIDENCE_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_args(env::args().skip(1))?;
    let database_url = read_secret("AGENT_TRUST_EVIDENCE_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_EVIDENCE_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_EVIDENCE_DATABASE_CA_FILE", false)?;
    let expected_role = required_identifier("AGENT_TRUST_EVIDENCE_DATABASE_EXPECTED_ROLE")?;
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(validate_database_url(
            &database_url,
            &database_ca,
            &database_password,
            &expected_role,
        )?)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;
    let signing_key = read_signing_key("AGENT_TRUST_EVIDENCE_SIGNING_PRIVATE_KEY_FILE")?;
    let verifying_keys = read_public_keyring("AGENT_TRUST_EVIDENCE_VERIFYING_KEYRING_FILE")?;
    let store = Arc::new(PostgresEvidenceStore::new(
        pool,
        required_identifier("AGENT_TRUST_EVIDENCE_ISSUER")?,
        required_identifier("AGENT_TRUST_EVIDENCE_SIGNING_KEY_ID")?,
        signing_key,
        verifying_keys,
    )?);
    let identities = parse_identities(&required_env("AGENT_TRUST_EVIDENCE_CLIENT_IDENTITIES")?)?;
    let authorizer = Arc::new(TokenBindingEvidenceAuthorizer::from_file(
        &required_file("AGENT_TRUST_EVIDENCE_TOKEN_BINDINGS_FILE", true)?,
        &identities,
    )?);
    let maximum_artifact_bytes = parse_size(
        "AGENT_TRUST_EVIDENCE_MAX_ARTIFACT_BYTES",
        1,
        64 * 1024 * 1024,
    )?;
    let worm = Arc::new(HttpWormArtifactStore::new(
        &required_env("AGENT_TRUST_EVIDENCE_WORM_ENDPOINT")?,
        read_secret("AGENT_TRUST_EVIDENCE_WORM_TOKEN_FILE")?.to_string(),
        &required_file("AGENT_TRUST_EVIDENCE_WORM_CA_FILE", false)?,
        &required_file("AGENT_TRUST_EVIDENCE_WORM_CERTIFICATE_FILE", false)?,
        &required_file("AGENT_TRUST_EVIDENCE_WORM_PRIVATE_KEY_FILE", true)?,
        maximum_artifact_bytes,
    )?);
    if !store.ready().await {
        return Err("EVIDENCE_DATABASE_NOT_READY".into());
    }
    serve(
        EvidenceServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_EVIDENCE_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file(
                "AGENT_TRUST_EVIDENCE_TLS_CERTIFICATE_FILE",
                false,
            )?,
            tls_private_key_file: required_file("AGENT_TRUST_EVIDENCE_TLS_PRIVATE_KEY_FILE", true)?,
            client_identities: identities,
            maximum_request_bytes: maximum_artifact_bytes
                .checked_add(maximum_artifact_bytes / 2)
                .and_then(|value| value.checked_add(1_048_576))
                .ok_or("EVIDENCE_MAX_ARTIFACT_BYTES_INVALID")?,
            maximum_artifact_bytes,
        },
        store,
        worm,
        authorizer,
    )
    .await?;
    Ok(())
}

fn validate_database_url(
    value: &str,
    ca_file: &Path,
    password: &str,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let mut normalized = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized_key = key.to_ascii_lowercase();
        if key.as_ref() != normalized_key
            || value.is_empty()
            || normalized
                .insert(normalized_key, value.into_owned())
                .is_some()
        {
            return Err("EVIDENCE_DATABASE_URL_INVALID".into());
        }
    }
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || parsed.path().trim_matches('/').is_empty()
        || parsed.path().trim_matches('/').contains('/')
        || parsed.fragment().is_some()
        || normalized.len() != 2
        || normalized.get("sslmode").map(String::as_str) != Some("verify-full")
        || normalized.get("options").map(String::as_str) != Some("-csearch_path=pg_catalog,public")
        || !ca_file.is_absolute()
        || password.is_empty()
        || password.len() > 65_536
    {
        return Err("EVIDENCE_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::from_str(value)?
        .password(password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file))
}

async fn verify_database_posture(
    pool: &sqlx::PgPool,
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
                rolreplication,rolinherit,current_setting('search_path') AS search_path,\
                current_schemas(false)::text AS resolved_schemas,current_setting('row_security') AS row_security,\
                has_schema_privilege(current_user,'public','CREATE') AS can_create,\
                has_database_privilege(current_user,current_database(),'TEMP') AS can_temp,\
                has_table_privilege(current_user,'audit_events','INSERT') AS can_insert_events,\
                has_table_privilege(current_user,'audit_events','UPDATE,DELETE') AS can_mutate_events,\
                has_table_privilege(current_user,'evidence_chain_heads','UPDATE') AS can_update_heads,\
                has_table_privilege(current_user,'evidence_event_requests','SELECT') AS can_read_event_requests,\
                has_table_privilege(current_user,'evidence_event_requests','INSERT') AS can_insert_event_requests,\
                has_table_privilege(current_user,'authority_evidence_event_requests','SELECT') AS can_read_authority_events,\
                has_table_privilege(current_user,'authority_evidence_event_requests','INSERT') AS can_insert_authority_events,\
                has_table_privilege(current_user,'executions','SELECT') AS can_read_ledger,\
                has_table_privilege(current_user,'pep_execution_authorizations','SELECT') AS can_read_pep,\
                has_table_privilege(current_user,'orchestrator_tasks','SELECT') AS can_read_tasks,\
                has_table_privilege(current_user,'orchestrator_ingress_actions','SELECT') AS can_read_ingress \
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
    if row.try_get::<String, _>("role_name")? != expected_role
        || row.try_get::<bool, _>("rolsuper")?
        || row.try_get::<bool, _>("rolbypassrls")?
        || row.try_get::<bool, _>("rolcreatedb")?
        || row.try_get::<bool, _>("rolcreaterole")?
        || row.try_get::<bool, _>("rolreplication")?
        || row.try_get::<bool, _>("rolinherit")?
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_temp")?
        || !row.try_get::<bool, _>("can_insert_events")?
        || row.try_get::<bool, _>("can_mutate_events")?
        || !row.try_get::<bool, _>("can_update_heads")?
        || !row.try_get::<bool, _>("can_read_event_requests")?
        || !row.try_get::<bool, _>("can_insert_event_requests")?
        || !row.try_get::<bool, _>("can_read_authority_events")?
        || !row.try_get::<bool, _>("can_insert_authority_events")?
        || !row.try_get::<bool, _>("can_read_ledger")?
        || !row.try_get::<bool, _>("can_read_pep")?
        || !row.try_get::<bool, _>("can_read_tasks")?
        || !row.try_get::<bool, _>("can_read_ingress")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("EVIDENCE_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8087_u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9097_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("EVIDENCE_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("EVIDENCE_ARGUMENTS_INVALID".into()),
        }
    }
    let data_ip: IpAddr = listen.parse()?;
    let management_ip: IpAddr = management_listen.parse()?;
    if port == 0
        || management_port == 0
        || port == management_port
        || !(management_ip.is_loopback() || management_ip.is_unspecified())
    {
        return Err("EVIDENCE_ARGUMENTS_INVALID".into());
    }
    Ok(Arguments {
        data: SocketAddr::new(data_ip, port),
        management: SocketAddr::new(management_ip, management_port),
    })
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
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn read_secret(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    if std::fs::metadata(&path)?.len() > 65_536 {
        return Err(format!("{name}_INVALID").into());
    }
    let value = std::fs::read_to_string(path)?;
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn read_signing_key(name: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let encoded = read_secret(name)?;
    let raw = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| format!("{name}_INVALID"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name}_INVALID"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn read_public_keyring(
    name: &str,
) -> Result<BTreeMap<String, VerifyingKey>, Box<dyn std::error::Error>> {
    let path = required_file(name, false)?;
    if std::fs::metadata(&path)?.len() > 1_048_576 {
        return Err(format!("{name}_INVALID").into());
    }
    let document: PublicKeyRing = serde_json::from_slice(&std::fs::read(path)?)?;
    if document.schema_version != "agenttrust.ed25519-public-keyring.v1"
        || document.keys.is_empty()
        || document.keys.len() > 1_024
    {
        return Err(format!("{name}_INVALID").into());
    }
    document
        .keys
        .into_iter()
        .map(
            |(key_id, encoded)| -> Result<_, Box<dyn std::error::Error>> {
                if key_id.is_empty() || key_id.len() > 128 {
                    return Err(format!("{name}_INVALID").into());
                }
                let bytes: [u8; 32] = URL_SAFE_NO_PAD
                    .decode(encoded.as_bytes())
                    .map_err(|_| format!("{name}_INVALID"))?
                    .try_into()
                    .map_err(|_| format!("{name}_INVALID"))?;
                let key =
                    VerifyingKey::from_bytes(&bytes).map_err(|_| format!("{name}_INVALID"))?;
                Ok((key_id, key))
            },
        )
        .collect::<Result<BTreeMap<_, _>, _>>()
}

fn required_file(name: &str, private: bool) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute() || !secure_file(&path, private)? {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(path)
}

fn parse_identities(value: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let values = value
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if values.is_empty()
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 512
                || !(value.starts_with("DNS:") || value.starts_with("URI:"))
        })
    {
        return Err("EVIDENCE_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(values)
}

fn parse_size(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let value = required_env(name)?.parse::<usize>()?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let allowed_bits = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
    let readable = (metadata.uid() == uid && mode & 0o400 != 0)
        || (metadata.gid() == gid && mode & 0o040 != 0);
    let access = if private {
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
fn secure_file(_path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_defaults_are_distinct() {
        let arguments = parse_args(Vec::new()).unwrap_or_else(|error| panic!("defaults: {error}"));
        assert_eq!(arguments.data.port(), 8087);
        assert_eq!(arguments.management.port(), 9097);
        assert!(parse_args(["--management-port".into(), "8087".into()]).is_err());
    }

    #[test]
    fn database_transport_is_pinned_and_password_is_out_of_band() {
        let ca = Path::new("/var/run/agenttrust/database-ca.pem");
        let valid = "postgresql://agenttrust_evidence@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic";
        assert!(validate_database_url(valid, ca, "separate", "agenttrust_evidence").is_ok());
        assert!(validate_database_url(
            "postgresql://agenttrust_evidence:embedded@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic",
            ca,
            "separate",
            "agenttrust_evidence"
        )
        .is_err());
    }
}
