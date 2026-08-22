use agent_trust_agent_registry_posture::production::{
    CursorCodec, HttpLifecyclePropagationPort, PostgresAgentRegistryAuthority,
};
use agent_trust_agent_registry_posture::server::{
    AgentRegistryServerConfig, TokenBindingAgentRegistryAuthorizer, serve,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Duration;
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    data: SocketAddr,
    management: SocketAddr,
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("AGENT_REGISTRY_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_args(env::args().skip(1))?;
    let database_url = read_secret("AGENT_TRUST_AGENT_REGISTRY_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_AGENT_REGISTRY_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_AGENT_REGISTRY_DATABASE_CA_FILE", false)?;
    let expected_role = required_identifier("AGENT_TRUST_AGENT_REGISTRY_DATABASE_EXPECTED_ROLE")?;
    let connect = validate_database_url(
        &database_url,
        &database_ca,
        &database_password,
        &expected_role,
    )?;
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(connect)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;

    let lifecycle_ca = std::fs::read(required_file(
        "AGENT_TRUST_AGENT_REGISTRY_LIFECYCLE_CA_FILE",
        false,
    )?)?;
    let mut lifecycle_identity = std::fs::read(required_file(
        "AGENT_TRUST_AGENT_REGISTRY_LIFECYCLE_CLIENT_CERTIFICATE_FILE",
        false,
    )?)?;
    lifecycle_identity.extend_from_slice(b"\n");
    lifecycle_identity.extend_from_slice(&std::fs::read(required_file(
        "AGENT_TRUST_AGENT_REGISTRY_LIFECYCLE_CLIENT_PRIVATE_KEY_FILE",
        true,
    )?)?);
    let lifecycle = Arc::new(HttpLifecyclePropagationPort::new(
        Url::parse(&required_env(
            "AGENT_TRUST_AGENT_REGISTRY_LIFECYCLE_BASE_URL",
        )?)?,
        &lifecycle_ca,
        &lifecycle_identity,
        read_secret("AGENT_TRUST_AGENT_REGISTRY_IDENTITY_REVOCATION_TOKEN_FILE")?,
        read_secret("AGENT_TRUST_AGENT_REGISTRY_AUTHORIZATION_REVOCATION_TOKEN_FILE")?,
        read_secret("AGENT_TRUST_AGENT_REGISTRY_PACK_DEACTIVATION_TOKEN_FILE")?,
    )?);
    let cursor = CursorCodec::new(
        read_cursor_key(&required_file(
            "AGENT_TRUST_AGENT_REGISTRY_CURSOR_HMAC_KEY_FILE",
            true,
        )?)?,
        Duration::minutes(15),
    )?;
    let authority = Arc::new(PostgresAgentRegistryAuthority::new(pool, lifecycle, cursor));
    let identities = parse_identities(&required_env(
        "AGENT_TRUST_AGENT_REGISTRY_CLIENT_IDENTITIES",
    )?)?;
    let bindings = required_file("AGENT_TRUST_AGENT_REGISTRY_TOKEN_BINDINGS_FILE", true)?;
    let authorizer = Arc::new(TokenBindingAgentRegistryAuthorizer::from_file(
        &bindings,
        &identities,
    )?);
    if !authority.ready(authorizer.tenants(), true).await {
        return Err("AGENT_REGISTRY_AUTHORITY_NOT_READY".into());
    }
    serve(
        AgentRegistryServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_AGENT_REGISTRY_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file(
                "AGENT_TRUST_AGENT_REGISTRY_TLS_CERTIFICATE_FILE",
                false,
            )?,
            tls_private_key_file: required_file(
                "AGENT_TRUST_AGENT_REGISTRY_TLS_PRIVATE_KEY_FILE",
                true,
            )?,
            client_identities: identities,
        },
        authority,
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
    let parsed = Url::parse(value)?;
    let mut normalized = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized_key = key.to_ascii_lowercase();
        if key.as_ref() != normalized_key
            || value.is_empty()
            || normalized
                .insert(normalized_key, value.into_owned())
                .is_some()
        {
            return Err("AGENT_REGISTRY_DATABASE_URL_INVALID".into());
        }
    }
    let database_name = parsed.path().trim_matches('/');
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || database_name.is_empty()
        || database_name.len() > 128
        || !database_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        || parsed.fragment().is_some()
        || normalized.len() != 2
        || normalized.get("sslmode").map(String::as_str) != Some("verify-full")
        || normalized.get("options").map(String::as_str) != Some("-csearch_path=pg_catalog,public")
        || !ca_file.is_absolute()
        || password.is_empty()
        || password.len() > 65_536
    {
        return Err("AGENT_REGISTRY_DATABASE_URL_INVALID".into());
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
                (has_table_privilege(current_user,'agent_assets','SELECT') AND\
                 has_table_privilege(current_user,'agent_assets','INSERT') AND\
                 has_table_privilege(current_user,'agent_assets','UPDATE')) AS assets_required,\
                has_table_privilege(current_user,'agent_assets','DELETE') AS assets_delete,\
                (has_table_privilege(current_user,'agent_discovery_facts','SELECT') AND has_table_privilege(current_user,'agent_discovery_facts','INSERT')) AS discovery_required,\
                (has_table_privilege(current_user,'agent_discovery_facts','UPDATE') OR has_table_privilege(current_user,'agent_discovery_facts','DELETE')) AS discovery_mutate,\
                (has_table_privilege(current_user,'agent_posture_findings','SELECT') AND has_table_privilege(current_user,'agent_posture_findings','INSERT')) AS posture_required,\
                (has_table_privilege(current_user,'agent_posture_findings','UPDATE') OR has_table_privilege(current_user,'agent_posture_findings','DELETE')) AS posture_mutate,\
                (has_table_privilege(current_user,'agent_boms','SELECT') AND has_table_privilege(current_user,'agent_boms','INSERT')) AS boms_required,\
                (has_table_privilege(current_user,'agent_ownership_confirmations','SELECT') AND has_table_privilege(current_user,'agent_ownership_confirmations','INSERT')) AS ownership_required,\
                (has_table_privilege(current_user,'agent_relationship_edges','SELECT') AND has_table_privilege(current_user,'agent_relationship_edges','INSERT')) AS relationships_required,\
                (has_table_privilege(current_user,'agent_relationship_supersessions','SELECT') AND has_table_privilege(current_user,'agent_relationship_supersessions','INSERT')) AS relationship_supersessions_required,\
                (has_table_privilege(current_user,'agent_posture_resolutions','SELECT') AND has_table_privilege(current_user,'agent_posture_resolutions','INSERT')) AS resolutions_required,\
                (has_table_privilege(current_user,'agent_lifecycle_records','SELECT') AND has_table_privilege(current_user,'agent_lifecycle_records','INSERT')) AS lifecycle_required,\
                (has_table_privilege(current_user,'agent_registry_idempotency','SELECT') AND has_table_privilege(current_user,'agent_registry_idempotency','INSERT')) AS idem_required,\
                (has_table_privilege(current_user,'agent_registry_audit_heads','SELECT') AND has_table_privilege(current_user,'agent_registry_audit_heads','INSERT') AND has_table_privilege(current_user,'agent_registry_audit_heads','UPDATE')) AS heads_required,\
                (has_table_privilege(current_user,'agent_registry_audit_events','SELECT') AND has_table_privilege(current_user,'agent_registry_audit_events','INSERT')) AS audit_required,\
                (has_table_privilege(current_user,'agent_registry_outbox','SELECT') AND has_table_privilege(current_user,'agent_registry_outbox','INSERT')) AS outbox_required,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants g \
                 WHERE g.grantee=current_user AND g.table_schema='public' AND g.table_name=ANY(ARRAY[\
                   'agent_assets','agent_discovery_facts','agent_posture_findings','agent_boms',\
                   'agent_ownership_confirmations','agent_relationship_edges',\
                   'agent_relationship_supersessions','agent_posture_resolutions',\
                   'agent_lifecycle_records','agent_registry_idempotency','agent_registry_audit_heads',\
                   'agent_registry_audit_events','agent_registry_outbox'\
                 ]) AND NOT (\
                   (g.table_name IN ('agent_assets','agent_registry_audit_heads') AND g.privilege_type IN ('SELECT','INSERT','UPDATE')) OR\
                   (g.table_name NOT IN ('agent_assets','agent_registry_audit_heads') AND g.privilege_type IN ('SELECT','INSERT'))\
                 )) AS excessive_table_privilege \
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
    for field in [
        "assets_required",
        "discovery_required",
        "posture_required",
        "boms_required",
        "ownership_required",
        "relationships_required",
        "relationship_supersessions_required",
        "resolutions_required",
        "lifecycle_required",
        "idem_required",
        "heads_required",
        "audit_required",
        "outbox_required",
    ] {
        if !row.try_get::<bool, _>(field)? {
            return Err("AGENT_REGISTRY_DATABASE_GRANTS_UNSAFE".into());
        }
    }
    if row.try_get::<String, _>("role_name")? != expected_role
        || row.try_get::<bool, _>("rolsuper")?
        || row.try_get::<bool, _>("rolbypassrls")?
        || row.try_get::<bool, _>("rolcreatedb")?
        || row.try_get::<bool, _>("rolcreaterole")?
        || row.try_get::<bool, _>("rolreplication")?
        || row.try_get::<bool, _>("rolinherit")?
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_temp")?
        || row.try_get::<bool, _>("assets_delete")?
        || row.try_get::<bool, _>("discovery_mutate")?
        || row.try_get::<bool, _>("posture_mutate")?
        || row.try_get::<bool, _>("excessive_table_privilege")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("AGENT_REGISTRY_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8089_u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9099_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("AGENT_REGISTRY_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("AGENT_REGISTRY_ARGUMENTS_INVALID".into()),
        }
    }
    let data_ip: IpAddr = listen.parse()?;
    let management_ip: IpAddr = management_listen.parse()?;
    if port == 0
        || management_port == 0
        || port == management_port
        || !(management_ip.is_loopback() || management_ip.is_unspecified())
    {
        return Err("AGENT_REGISTRY_ARGUMENTS_INVALID".into());
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

fn read_cursor_key(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encoded = std::fs::read_to_string(path)?;
    if encoded.is_empty()
        || encoded.contains('\n')
        || encoded.contains('\r')
        || encoded.contains('=')
    {
        return Err("AGENT_REGISTRY_CURSOR_KEY_INVALID".into());
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    if !(32..=64).contains(&decoded.len()) {
        return Err("AGENT_REGISTRY_CURSOR_KEY_INVALID".into());
    }
    Ok(decoded)
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
        return Err("AGENT_REGISTRY_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(values)
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let access = if private {
        private_file_access_allowed(mode, metadata.uid(), metadata.gid(), uid, gid)
    } else {
        mode & 0o022 == 0
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() > 0
        && metadata.len() <= 1_048_576
        && access)
}

#[cfg(unix)]
fn private_file_access_allowed(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    effective_uid: u32,
    effective_gid: u32,
) -> bool {
    let allowed_bits = 0o400 | if file_gid == effective_gid { 0o040 } else { 0 };
    let actually_readable = (file_uid == effective_uid && mode & 0o400 != 0)
        || (file_gid == effective_gid && mode & 0o040 != 0);
    actually_readable && mode & !allowed_bits == 0
}

#[cfg(not(unix))]
fn secure_file(_path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_defaults_are_separate() {
        let arguments = parse_args(Vec::new()).unwrap_or_else(|error| panic!("defaults: {error}"));
        assert_eq!(arguments.data.port(), 8089);
        assert_eq!(arguments.management.port(), 9099);
        assert!(parse_args(["--management-port".into(), "8089".into()]).is_err());
    }

    #[test]
    fn database_url_requires_separate_secret_verify_full_and_exact_role() {
        let ca = Path::new("/var/run/agenttrust/database-ca.pem");
        let valid = "postgresql://agenttrust_agent_registry@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic";
        assert!(
            validate_database_url(valid, ca, "separate-secret", "agenttrust_agent_registry")
                .is_ok()
        );
        assert!(validate_database_url(
            "postgresql://agenttrust_agent_registry:embedded@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic",
            ca,
            "separate-secret",
            "agenttrust_agent_registry"
        )
        .is_err());
        assert!(validate_database_url(valid, ca, "separate-secret", "wrong_role").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_files_reject_excess_permissions() {
        assert!(private_file_access_allowed(0o400, 1000, 2000, 1000, 3000));
        assert!(private_file_access_allowed(0o440, 1000, 3000, 1000, 3000));
        assert!(!private_file_access_allowed(0o600, 1000, 2000, 1000, 3000));
        assert!(!private_file_access_allowed(0o444, 1000, 3000, 1000, 3000));
    }
}
