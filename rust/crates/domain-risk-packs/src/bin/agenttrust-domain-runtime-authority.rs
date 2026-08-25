use agent_trust_domain_risk_packs::authority::{
    DomainReceiptKeyring, DomainRuntimeAuthority, PostgresDomainRuntimeStore,
};
use agent_trust_domain_risk_packs::server::{
    DomainServerConfig, DomainTokenAuthorizer, HttpDomainRuntimePort, router, serve,
};
use agent_trust_pack_supply_chain::server::{EvidenceEventKeyring, SupplyDependency};
use reqwest::{Certificate, Identity};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("DOMAIN_RUNTIME_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if nix::unistd::Uid::effective().is_root() {
        return Err("DOMAIN_RUNTIME_ROOT_PROCESS_DENIED".into());
    }
    let database_url = read_secret("AGENT_TRUST_DOMAIN_DATABASE_URL_FILE", 16, 16_384)?;
    let mut password = read_secret("AGENT_TRUST_DOMAIN_DATABASE_PASSWORD_FILE", 16, 8192)?;
    let role = required_identifier("AGENT_TRUST_DOMAIN_DATABASE_EXPECTED_ROLE")?;
    let options = database_options(
        &database_url,
        &password,
        &required_path("AGENT_TRUST_DOMAIN_DATABASE_CA_FILE")?,
        &role,
    )?;
    password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    verify_role(&pool, &role).await?;
    let client = outbound_client(
        &required_path("AGENT_TRUST_DOMAIN_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_DOMAIN_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_DOMAIN_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let executor = dependency("EXECUTOR", "executor")?;
    let evidence = dependency("EVIDENCE", "evidence")?;
    let evidence_keyring = EvidenceEventKeyring::from_json(&std::fs::read(
        required_private_path("AGENT_TRUST_DOMAIN_EVIDENCE_KEYRING_FILE")?,
    )?)?;
    let runtime = Arc::new(HttpDomainRuntimePort::new(
        client,
        executor,
        evidence,
        evidence_keyring,
        required_identity("AGENT_TRUST_DOMAIN_EVIDENCE_CLIENT_IDENTITY")?,
    )?);
    let receipt_keyring = DomainReceiptKeyring::from_json(
        &std::fs::read(required_private_path(
            "AGENT_TRUST_DOMAIN_RECEIPT_KEYRING_FILE",
        )?)?,
        chrono::Utc::now(),
    )?;
    let authority = DomainRuntimeAuthority::new(
        PostgresDomainRuntimeStore::new(pool),
        runtime.clone(),
        receipt_keyring,
        Uuid::parse_str(&required_uuid("AGENT_TRUST_DOMAIN_INSTANCE_ID")?)?,
        required_i64("AGENT_TRUST_DOMAIN_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;
    let identities = required_identities("AGENT_TRUST_DOMAIN_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(DomainTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_DOMAIN_TOKEN_BINDINGS_FILE")?,
        &identities,
    )?);
    let application = router(authority.clone(), tokens, runtime);
    serve(
        DomainServerConfig {
            data_address: SocketAddr::new(
                env::var("AGENT_TRUST_DOMAIN_LISTEN_ADDRESS")?.parse::<IpAddr>()?,
                required_i64("AGENT_TRUST_DOMAIN_PORT", 8094, 8094)? as u16,
            ),
            management_address: SocketAddr::new(
                env::var("AGENT_TRUST_DOMAIN_MANAGEMENT_LISTEN_ADDRESS")?.parse::<IpAddr>()?,
                required_i64("AGENT_TRUST_DOMAIN_MANAGEMENT_PORT", 9104, 9104)? as u16,
            ),
            tls_ca_file: required_path("AGENT_TRUST_DOMAIN_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_DOMAIN_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path("AGENT_TRUST_DOMAIN_TLS_PRIVATE_KEY_FILE")?,
            allowed_client_identities: identities,
        },
        application,
        authority,
    )
    .await?;
    Ok(())
}
fn dependency(suffix: &str, name: &str) -> Result<SupplyDependency, Box<dyn std::error::Error>> {
    Ok(SupplyDependency {
        name: name.into(),
        endpoint: required_url(&format!("AGENT_TRUST_DOMAIN_{suffix}_ENDPOINT"))?,
        token_file: required_private_path(&format!("AGENT_TRUST_DOMAIN_{suffix}_TOKEN_FILE"))?,
        readiness_schema: required_identifier(&format!(
            "AGENT_TRUST_DOMAIN_{suffix}_READINESS_SCHEMA"
        ))?,
    })
}
async fn verify_role(
    pool: &sqlx::PgPool,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row=sqlx::query("SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication,rolinherit,rolcanlogin,current_setting('search_path') AS search_path,current_schemas(true)::text AS schemas,current_setting('row_security') AS row_security,has_schema_privilege(current_user,'public','CREATE') AS can_create,has_database_privilege(current_user,current_database(),'TEMP') AS can_temp FROM pg_roles WHERE rolname=current_user").fetch_one(pool).await?;
    if row.try_get::<String, _>("role_name")? != expected
        || row.try_get::<bool, _>("rolsuper")?
        || row.try_get::<bool, _>("rolbypassrls")?
        || row.try_get::<bool, _>("rolcreatedb")?
        || row.try_get::<bool, _>("rolcreaterole")?
        || row.try_get::<bool, _>("rolreplication")?
        || row.try_get::<bool, _>("rolinherit")?
        || !row.try_get::<bool, _>("rolcanlogin")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_temp")?
    {
        return Err("DOMAIN_RUNTIME_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}
fn database_options(
    value: &str,
    password: &str,
    ca: &Path,
    role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized = key.to_ascii_lowercase();
        if key.as_ref() != normalized
            || value.is_empty()
            || query.insert(normalized, value.into_owned()).is_some()
        {
            return Err("DOMAIN_RUNTIME_DATABASE_URL_INVALID".into());
        }
    }
    let database = parsed.path().strip_prefix('/').unwrap_or("");
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != role
        || parsed.password().is_some()
        || database.is_empty()
        || database.len() > 63
        || database.contains('/')
        || parsed.fragment().is_some()
        || password.is_empty()
        || query.len() != 2
        || query.get("sslmode").map(String::as_str) != Some("verify-full")
        || query.get("options").map(String::as_str) != Some("-csearch_path=pg_catalog,public")
    {
        return Err("DOMAIN_RUNTIME_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::from_str(value)?
        .password(password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca))
}
fn outbound_client(
    ca: &Path,
    certificate: &Path,
    key_path: &Path,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let ca = Certificate::from_pem(&std::fs::read(ca)?)?;
    let mut pem = std::fs::read(certificate)?;
    let mut key = std::fs::read(key_path)?;
    pem.extend_from_slice(b"\n");
    pem.extend_from_slice(&key);
    key.zeroize();
    let identity = Identity::from_pem(&pem)?;
    pem.zeroize();
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(ca)
        .identity(identity)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(60))
        .build()?)
}
fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, false)? {
        return Err("DOMAIN_RUNTIME_FILE_INVALID".into());
    }
    Ok(path)
}
fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, true)? {
        return Err("DOMAIN_RUNTIME_PRIVATE_FILE_INVALID".into());
    }
    Ok(path)
}
fn secure_file(path: &Path, private: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    let uid = nix::unistd::Uid::effective().as_raw();
    let gid = nix::unistd::Gid::effective().as_raw();
    let access = if private {
        let allowed = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
        let readable = (metadata.uid() == uid && mode & 0o400 != 0)
            || (metadata.gid() == gid && mode & 0o040 != 0);
        readable && mode & !allowed == 0
    } else {
        mode & 0o022 == 0
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.nlink() == 1
        && metadata.len() > 0
        && metadata.len() <= 16 * 1024 * 1024
        && access)
}
fn read_secret(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::fs::read_to_string(required_private_path(name)?)?;
    let secret = value.trim_end_matches(['\r', '\n']);
    if !(minimum..=maximum).contains(&secret.len())
        || secret.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(secret.len()) > 2
    {
        return Err("DOMAIN_RUNTIME_SECRET_INVALID".into());
    }
    Ok(secret.into())
}
fn required_url(name: &str) -> Result<url::Url, Box<dyn std::error::Error>> {
    let value = url::Url::parse(&env::var(name)?)?;
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err("DOMAIN_RUNTIME_ENDPOINT_INVALID".into());
    }
    Ok(value)
}
fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty()
        || value.len() > 256
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@'))
        })
    {
        return Err("DOMAIN_RUNTIME_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}
fn required_identity(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_identifier(name)?;
    if !value
        .strip_prefix("DNS:")
        .or_else(|| value.strip_prefix("URI:"))
        .is_some_and(|identity| !identity.is_empty())
    {
        return Err("DOMAIN_RUNTIME_IDENTITY_INVALID".into());
    }
    Ok(value)
}
fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if !Uuid::parse_str(&value).is_ok_and(|parsed| parsed.to_string() == value) {
        return Err("DOMAIN_RUNTIME_UUID_INVALID".into());
    }
    Ok(value)
}
fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value: i64 = env::var(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("DOMAIN_RUNTIME_INTEGER_INVALID".into());
    }
    Ok(value)
}
fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let identities = env::var(name)?
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if identities.is_empty()
        || identities.len() > 64
        || identities.iter().any(|value| {
            value.len() > 512
                || !(value.starts_with("DNS:") || value.starts_with("URI:"))
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
        })
    {
        return Err("DOMAIN_RUNTIME_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}
