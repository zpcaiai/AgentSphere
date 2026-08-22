use agent_trust_contracts::{AgentInstanceId, ToolId, ToolVersion};
use agent_trust_enterprise_control::authority::{
    EnterpriseAuthorityConfig, EnterpriseExecutor, EnterpriseIngressAuthority,
    PostgresEnterpriseAuthorityStore, VaultKvCredentialAuthority,
};
use agent_trust_enterprise_control::principal::HumanPrincipalKeyring;
use agent_trust_enterprise_control::server::{
    EnterpriseServerConfig, EnterpriseTokenAuthorizer, HttpEnterpriseOrchestrator, router, serve,
};
use reqwest::{Certificate, Identity};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("ENTERPRISE_CONTROL_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = read_secret_file("AGENT_TRUST_ENTERPRISE_DATABASE_URL_FILE", 16, 16_384)?;
    let database_password =
        read_secret_file("AGENT_TRUST_ENTERPRISE_DATABASE_PASSWORD_FILE", 16, 8_192)?;
    let expected_role = required_identifier("AGENT_TRUST_ENTERPRISE_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_path("AGENT_TRUST_ENTERPRISE_DATABASE_CA_FILE")?;
    let options = database_options(
        &database_url,
        &database_password,
        &database_ca,
        &expected_role,
    )?;
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_ENTERPRISE_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_ENTERPRISE_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_ENTERPRISE_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let store = PostgresEnterpriseAuthorityStore::new(pool);
    let orchestrator = Arc::new(HttpEnterpriseOrchestrator::new(
        outbound.clone(),
        required_url("AGENT_TRUST_ENTERPRISE_ORCHESTRATOR_ENDPOINT")?,
        required_private_path("AGENT_TRUST_ENTERPRISE_ORCHESTRATOR_TOKEN_FILE")?,
    )?);
    let authority = EnterpriseIngressAuthority::new(
        store.clone(),
        orchestrator,
        EnterpriseAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_ENTERPRISE_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_ENTERPRISE_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_ENTERPRISE_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_ENTERPRISE_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_ENTERPRISE_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_ENTERPRISE_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_ENTERPRISE_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: required_identifier("AGENT_TRUST_ENTERPRISE_SERVICE_SUBJECT")?,
            assertion_scope: "enterprise:mutate".into(),
        },
    )?;
    let vault_token = Zeroizing::new(read_secret_file(
        "AGENT_TRUST_ENTERPRISE_VAULT_TOKEN_FILE",
        16,
        8_192,
    )?);
    let pepper = Zeroizing::new(read_binary_secret(
        "AGENT_TRUST_ENTERPRISE_API_KEY_PEPPER_FILE",
        32,
        4_096,
    )?);
    let credential_authority = Arc::new(VaultKvCredentialAuthority::new(
        outbound,
        required_url("AGENT_TRUST_ENTERPRISE_VAULT_ENDPOINT")?,
        required_identifier("AGENT_TRUST_ENTERPRISE_VAULT_KV_MOUNT")?,
        required_path_prefix("AGENT_TRUST_ENTERPRISE_VAULT_KV_PREFIX")?,
        vault_token,
        pepper,
    )?);
    let executor = EnterpriseExecutor::new(store, credential_authority);
    let allowed_identities = required_identities("AGENT_TRUST_ENTERPRISE_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(EnterpriseTokenAuthorizer::from_file(
        &required_path("AGENT_TRUST_ENTERPRISE_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let audience = required_identifier("AGENT_TRUST_HUMAN_PRINCIPAL_AUDIENCE")?;
    let keyring = Arc::new(HumanPrincipalKeyring::from_file(
        &required_path("AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE")?,
        &audience,
    )?);
    let service_subject = required_identifier("AGENT_TRUST_ENTERPRISE_SERVICE_SUBJECT")?;
    let readiness = authority.clone();
    let application = router(
        authority,
        executor,
        tokens,
        keyring,
        service_subject.clone(),
        required_i64(
            "AGENT_TRUST_ENTERPRISE_MAXIMUM_AUTHENTICATION_AGE_SECONDS",
            60,
            86_400,
        )?,
    );
    let listen: IpAddr = env::var("AGENT_TRUST_ENTERPRISE_LISTEN_ADDRESS")?.parse()?;
    let port = required_i64("AGENT_TRUST_ENTERPRISE_PORT", 1, 65_535)? as u16;
    serve(
        EnterpriseServerConfig {
            data_address: SocketAddr::new(listen, port),
            management_address: SocketAddr::new(
                env::var("AGENT_TRUST_ENTERPRISE_MANAGEMENT_LISTEN_ADDRESS")?.parse()?,
                required_i64("AGENT_TRUST_ENTERPRISE_MANAGEMENT_PORT", 1, 65_535)? as u16,
            ),
            tls_ca_file: required_path("AGENT_TRUST_ENTERPRISE_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_ENTERPRISE_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_ENTERPRISE_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: allowed_identities,
            service_subject,
            maximum_authentication_age_seconds: required_i64(
                "AGENT_TRUST_ENTERPRISE_MAXIMUM_AUTHENTICATION_AGE_SECONDS",
                60,
                86_400,
            )?,
        },
        application,
        readiness,
    )
    .await?;
    Ok(())
}

async fn verify_database_role(
    pool: &sqlx::PgPool,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
         rolreplication,rolinherit,rolcanlogin,current_setting('search_path') AS search_path,\
         current_schemas(true)::text AS schemas,current_setting('row_security') AS row_security,\
         has_schema_privilege(current_user,'public','CREATE') AS can_create,\
         has_database_privilege(current_user,current_database(),'TEMP') AS can_temp \
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
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
        return Err("ENTERPRISE_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn database_options(
    value: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized = key.to_ascii_lowercase();
        if key.as_ref() != normalized
            || value.is_empty()
            || query.insert(normalized, value.into_owned()).is_some()
        {
            return Err("ENTERPRISE_DATABASE_URL_INVALID".into());
        }
    }
    let database = parsed.path().strip_prefix('/').unwrap_or("");
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || database.is_empty()
        || database.len() > 63
        || database
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')))
        || parsed.fragment().is_some()
        || password.is_empty()
        || query.len() != 2
        || query.get("sslmode").map(String::as_str) != Some("verify-full")
        || query.get("options").map(String::as_str) != Some("-csearch_path=pg_catalog,public")
        || !ca_file.is_absolute()
    {
        return Err("ENTERPRISE_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::from_str(value)?
        .password(password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file))
}

fn outbound_client(
    ca: &Path,
    certificate: &Path,
    private_key: &Path,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let ca = Certificate::from_pem(&std::fs::read(ca)?)?;
    let mut identity_pem = std::fs::read(certificate)?;
    let mut key = std::fs::read(private_key)?;
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key);
    key.zeroize();
    let identity = Identity::from_pem(&identity_pem)?;
    identity_pem.zeroize();
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(ca)
        .identity(identity)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .build()?)
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, false)? {
        return Err("ENTERPRISE_REQUIRED_FILE_INVALID".into());
    }
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, true)? {
        return Err("ENTERPRISE_PRIVATE_FILE_INVALID".into());
    }
    Ok(path)
}

fn read_secret_file(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_private_path(name)?;
    let value = std::fs::read_to_string(path)?;
    let secret = value.trim_end_matches(['\r', '\n']);
    if !(minimum..=maximum).contains(&secret.len())
        || secret.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(secret.len()) > 2
    {
        return Err("ENTERPRISE_SECRET_FILE_INVALID".into());
    }
    Ok(secret.to_string())
}

fn read_binary_secret(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value = std::fs::read(required_private_path(name)?)?;
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
    {
        value.pop();
    }
    if !(minimum..=maximum).contains(&value.len()) {
        value.zeroize();
        return Err("ENTERPRISE_SECRET_FILE_INVALID".into());
    }
    Ok(value)
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
        return Err("ENTERPRISE_ENDPOINT_INVALID".into());
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
        return Err("ENTERPRISE_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if !uuid::Uuid::parse_str(&value).is_ok_and(|parsed| parsed.to_string() == value) {
        return Err("ENTERPRISE_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value: i64 = env::var(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("ENTERPRISE_INTEGER_INVALID".into());
    }
    Ok(value)
}

fn required_path_prefix(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty()
        || value.len() > 128
        || value.split('/').any(|segment| {
            segment.is_empty()
                || segment.len() > 128
                || segment.bytes().any(|byte| {
                    !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
                })
        })
    {
        return Err("ENTERPRISE_PATH_PREFIX_INVALID".into());
    }
    Ok(value)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let identities = env::var(name)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if identities.is_empty() || identities.len() > 32 {
        return Err("ENTERPRISE_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let access = if private {
        let allowed = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
        let readable = metadata.uid() == uid && mode & 0o400 != 0
            || metadata.gid() == gid && mode & 0o040 != 0;
        readable && mode & !allowed == 0
    } else {
        mode & 0o022 == 0
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() > 0
        && metadata.len() <= 4 * 1_048_576
        && access)
}

#[cfg(not(unix))]
fn secure_file(_path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    Ok(false)
}
