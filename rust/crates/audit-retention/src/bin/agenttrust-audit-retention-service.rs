use agent_trust_audit_retention::production::{
    HttpRetentionDeletionClient, PostgresAuditAuthority,
};
use agent_trust_audit_retention::server::{
    AuditServerConfig, HumanPrincipalAuditVerifier, TokenBindingAuditAuthorizer, serve,
};
use agent_trust_evidence_evaluator::artifact::HttpWormArtifactStore;
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
        eprintln!("AUDIT_RETENTION_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_args(env::args().skip(1))?;
    let database_url = read_secret("AGENT_TRUST_AUDIT_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_AUDIT_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_AUDIT_DATABASE_CA_FILE", false)?;
    let expected_role = required_identifier("AGENT_TRUST_AUDIT_DATABASE_EXPECTED_ROLE")?;
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

    let maximum_export_bytes = parse_size(
        "AGENT_TRUST_AUDIT_MAX_EXPORT_BYTES",
        1_048_576,
        64 * 1024 * 1024,
    )?;
    let worm = Arc::new(HttpWormArtifactStore::new(
        &required_env("AGENT_TRUST_AUDIT_WORM_ENDPOINT")?,
        read_secret("AGENT_TRUST_AUDIT_WORM_TOKEN_FILE")?,
        &required_file("AGENT_TRUST_AUDIT_WORM_CA_FILE", false)?,
        &required_file("AGENT_TRUST_AUDIT_WORM_CERTIFICATE_FILE", false)?,
        &required_file("AGENT_TRUST_AUDIT_WORM_PRIVATE_KEY_FILE", true)?,
        maximum_export_bytes,
    )?);
    let deletion = Arc::new(HttpRetentionDeletionClient::new(
        &required_env("AGENT_TRUST_AUDIT_DELETION_ENDPOINT")?,
        read_secret("AGENT_TRUST_AUDIT_DELETION_TOKEN_FILE")?,
        &required_file("AGENT_TRUST_AUDIT_DELETION_CA_FILE", false)?,
        &required_file("AGENT_TRUST_AUDIT_DELETION_CERTIFICATE_FILE", false)?,
        &required_file("AGENT_TRUST_AUDIT_DELETION_PRIVATE_KEY_FILE", true)?,
    )?);
    let signing_key = read_signing_key("AGENT_TRUST_AUDIT_SIGNING_PRIVATE_KEY_FILE")?;
    let verifying_keys = read_public_keyring("AGENT_TRUST_AUDIT_VERIFYING_KEYRING_FILE")?;
    let authority = Arc::new(PostgresAuditAuthority::new(
        pool,
        required_identifier("AGENT_TRUST_AUDIT_ISSUER")?,
        required_identifier("AGENT_TRUST_AUDIT_SIGNING_KEY_ID")?,
        signing_key,
        worm,
        deletion,
        maximum_export_bytes,
        verifying_keys,
    )?);
    let identities = parse_identities(&required_env("AGENT_TRUST_AUDIT_CLIENT_IDENTITIES")?)?;
    let authorizer = Arc::new(TokenBindingAuditAuthorizer::from_file(
        &required_file("AGENT_TRUST_AUDIT_TOKEN_BINDINGS_FILE", true)?,
        &identities,
    )?);
    let require_strong_auth = required_boolean("AGENT_TRUST_AUDIT_QUERY_REQUIRE_STRONG_AUTH")?;
    if !require_strong_auth {
        return Err("AGENT_TRUST_AUDIT_QUERY_REQUIRE_STRONG_AUTH_INVALID".into());
    }
    let human_principals = Arc::new(HumanPrincipalAuditVerifier::from_file(
        required_file("AGENT_TRUST_AUDIT_HUMAN_ASSERTION_KEYRING_FILE", false)?,
        required_env("AGENT_TRUST_AUDIT_HUMAN_ASSERTION_AUDIENCE")?,
        required_env("AGENT_TRUST_AUDIT_HUMAN_ASSERTION_MAX_AUTHENTICATION_AGE_SECONDS")?
            .parse::<i64>()?,
        require_strong_auth,
    )?);
    if !authority.ready().await {
        return Err("AUDIT_RETENTION_DEPENDENCIES_NOT_READY".into());
    }
    serve(
        AuditServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_AUDIT_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file("AGENT_TRUST_AUDIT_TLS_CERTIFICATE_FILE", false)?,
            tls_private_key_file: required_file("AGENT_TRUST_AUDIT_TLS_PRIVATE_KEY_FILE", true)?,
            client_identities: identities,
            maximum_request_bytes: parse_size(
                "AGENT_TRUST_AUDIT_MAX_REQUEST_BYTES",
                65_536,
                16 * 1024 * 1024,
            )?,
        },
        authority,
        authorizer,
        human_principals,
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
            return Err("AUDIT_DATABASE_URL_INVALID".into());
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
        return Err("AUDIT_DATABASE_URL_INVALID".into());
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
                has_table_privilege(current_user,'audit_records','SELECT') AS records_select,\
                has_table_privilege(current_user,'audit_records','INSERT') AS records_insert,\
                has_table_privilege(current_user,'audit_records','UPDATE,DELETE') AS records_mutable,\
                has_table_privilege(current_user,'audit_chain_heads','SELECT') AS heads_select,\
                has_table_privilege(current_user,'audit_chain_heads','INSERT') AS heads_insert,\
                has_table_privilege(current_user,'audit_chain_heads','UPDATE') AS heads_update,\
                has_table_privilege(current_user,'audit_chain_heads','DELETE') AS heads_delete,\
                has_table_privilege(current_user,'legal_holds','SELECT') AS holds_select,\
                has_table_privilege(current_user,'legal_holds','INSERT') AS holds_insert,\
                has_table_privilege(current_user,'legal_holds','UPDATE') AS holds_table_update,\
                has_column_privilege(current_user,'legal_holds','released_by','UPDATE') AS holds_release_actor,\
                has_column_privilege(current_user,'legal_holds','released_at','UPDATE') AS holds_release_time,\
                has_column_privilege(current_user,'legal_holds','release_reason','UPDATE') AS holds_release_reason,\
                has_table_privilege(current_user,'legal_holds','DELETE') AS holds_delete,\
                has_table_privilege(current_user,'audit_operation_replays','SELECT') AS replay_select,\
                has_table_privilege(current_user,'audit_operation_replays','INSERT') AS replay_insert,\
                has_table_privilege(current_user,'audit_export_manifests','SELECT') AS export_select,\
                has_table_privilege(current_user,'audit_export_manifests','INSERT') AS export_insert,\
                has_table_privilege(current_user,'audit_deletion_proofs','SELECT') AS deletion_select,\
                has_table_privilege(current_user,'audit_deletion_proofs','INSERT') AS deletion_insert,\
                has_table_privilege(current_user,'audit_retention_outbox','SELECT') AS outbox_select,\
                has_table_privilege(current_user,'audit_retention_outbox','INSERT') AS outbox_insert,\
                has_table_privilege(current_user,'audit_human_assertion_uses','SELECT') AS human_uses_select,\
                has_table_privilege(current_user,'audit_human_assertion_uses','INSERT') AS human_uses_insert,\
                has_table_privilege(current_user,'audit_retention_policies','SELECT') AS policies_select,\
                has_table_privilege(current_user,'audit_retention_policies','INSERT') AS policies_insert,\
                has_table_privilege(current_user,'audit_control_definitions','SELECT') AS controls_select,\
                has_table_privilege(current_user,'audit_control_definitions','INSERT') AS controls_insert,\
                has_table_privilege(current_user,'audit_evidence_nodes','SELECT') AS nodes_select,\
                has_table_privilege(current_user,'audit_evidence_nodes','INSERT') AS nodes_insert,\
                has_table_privilege(current_user,'audit_evidence_edges','SELECT') AS edges_select,\
                has_table_privilege(current_user,'audit_evidence_edges','INSERT') AS edges_insert,\
                (has_table_privilege(current_user,'audit_retention_policies','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_export_manifests','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_deletion_proofs','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_operation_replays','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_retention_outbox','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_human_assertion_uses','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_control_definitions','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_evidence_nodes','UPDATE,DELETE') OR\
                 has_table_privilege(current_user,'audit_evidence_edges','UPDATE,DELETE')) AS immutable_mutate \
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
        || !row.try_get::<bool, _>("records_select")?
        || !row.try_get::<bool, _>("records_insert")?
        || row.try_get::<bool, _>("records_mutable")?
        || !row.try_get::<bool, _>("heads_select")?
        || !row.try_get::<bool, _>("heads_insert")?
        || !row.try_get::<bool, _>("heads_update")?
        || row.try_get::<bool, _>("heads_delete")?
        || !row.try_get::<bool, _>("holds_select")?
        || !row.try_get::<bool, _>("holds_insert")?
        || row.try_get::<bool, _>("holds_table_update")?
        || !row.try_get::<bool, _>("holds_release_actor")?
        || !row.try_get::<bool, _>("holds_release_time")?
        || !row.try_get::<bool, _>("holds_release_reason")?
        || row.try_get::<bool, _>("holds_delete")?
        || !row.try_get::<bool, _>("replay_select")?
        || !row.try_get::<bool, _>("replay_insert")?
        || !row.try_get::<bool, _>("export_select")?
        || !row.try_get::<bool, _>("export_insert")?
        || !row.try_get::<bool, _>("deletion_select")?
        || !row.try_get::<bool, _>("deletion_insert")?
        || !row.try_get::<bool, _>("outbox_select")?
        || !row.try_get::<bool, _>("outbox_insert")?
        || !row.try_get::<bool, _>("human_uses_select")?
        || !row.try_get::<bool, _>("human_uses_insert")?
        || !row.try_get::<bool, _>("policies_select")?
        || !row.try_get::<bool, _>("policies_insert")?
        || !row.try_get::<bool, _>("controls_select")?
        || !row.try_get::<bool, _>("controls_insert")?
        || !row.try_get::<bool, _>("nodes_select")?
        || !row.try_get::<bool, _>("nodes_insert")?
        || !row.try_get::<bool, _>("edges_select")?
        || !row.try_get::<bool, _>("edges_insert")?
        || row.try_get::<bool, _>("immutable_mutate")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("AUDIT_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8088_u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9098_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("AUDIT_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("AUDIT_ARGUMENTS_INVALID".into()),
        }
    }
    let data_ip: IpAddr = listen.parse()?;
    let management_ip: IpAddr = management_listen.parse()?;
    if port == 0
        || management_port == 0
        || port == management_port
        || !(management_ip.is_loopback() || management_ip.is_unspecified())
    {
        return Err("AUDIT_ARGUMENTS_INVALID".into());
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

fn required_boolean(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match required_env(name)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{name}_INVALID").into()),
    }
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
    let raw = URL_SAFE_NO_PAD
        .decode(read_secret(name)?.as_bytes())
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
                if key_id.is_empty()
                    || key_id.len() > 128
                    || !key_id.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                    })
                {
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
        return Err("AUDIT_CLIENT_IDENTITIES_INVALID".into());
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
        assert_eq!(arguments.data.port(), 8088);
        assert_eq!(arguments.management.port(), 9098);
        assert!(parse_args(["--management-port".into(), "8088".into()]).is_err());
    }
}
