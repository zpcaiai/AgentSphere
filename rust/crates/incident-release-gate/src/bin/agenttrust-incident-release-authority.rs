use agent_trust_contracts::{AgentInstanceId, HumanPrincipalKeyring, ToolId, ToolVersion};
use agent_trust_incident_release_gate::authority::{
    IncidentAuthorityConfig, IncidentExecutor, IncidentIngressAuthority,
    PostgresIncidentAuthorityStore,
};
use agent_trust_incident_release_gate::server::{
    HttpIncidentEffectPort, HttpIncidentOrchestrator, IncidentServerConfig,
    IncidentTokenAuthorizer, router, serve,
};
use ed25519_dalek::SigningKey;
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
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("INCIDENT_RELEASE_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = read_secret_file("AGENT_TRUST_INCIDENT_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password =
        read_secret_file("AGENT_TRUST_INCIDENT_DATABASE_PASSWORD_FILE", 16, 8_192)?;
    let expected_role = required_identifier("AGENT_TRUST_INCIDENT_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_path("AGENT_TRUST_INCIDENT_DATABASE_CA_FILE")?;
    let options = database_options(
        &database_url,
        &database_password,
        &database_ca,
        &expected_role,
    )?;
    database_password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_INCIDENT_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_INCIDENT_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_INCIDENT_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let store = PostgresIncidentAuthorityStore::new(pool);
    let orchestrator = Arc::new(HttpIncidentOrchestrator::new(
        outbound.clone(),
        required_url("AGENT_TRUST_INCIDENT_ORCHESTRATOR_ENDPOINT")?,
        required_private_path("AGENT_TRUST_INCIDENT_ORCHESTRATOR_TOKEN_FILE")?,
    )?);
    let authority = IncidentIngressAuthority::new(
        store.clone(),
        orchestrator,
        IncidentAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_INCIDENT_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_INCIDENT_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_INCIDENT_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_INCIDENT_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_INCIDENT_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_INCIDENT_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_INCIDENT_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: required_identifier("AGENT_TRUST_INCIDENT_SERVICE_SUBJECT")?,
        },
    )?;
    let effects = Arc::new(HttpIncidentEffectPort::new(
        outbound,
        required_url("AGENT_TRUST_INCIDENT_CONTAINMENT_ENDPOINT")?,
        required_private_path("AGENT_TRUST_INCIDENT_CONTAINMENT_TOKEN_FILE")?,
        required_url("AGENT_TRUST_INCIDENT_REPLAY_ENDPOINT")?,
        required_private_path("AGENT_TRUST_INCIDENT_REPLAY_TOKEN_FILE")?,
    )?);
    let mut signing_key_bytes =
        read_binary_secret("AGENT_TRUST_INCIDENT_RELEASE_SIGNING_KEY_FILE", 32, 32)?;
    let signing_key_array: [u8; 32] = signing_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "INCIDENT_RELEASE_SIGNING_KEY_INVALID")?;
    let signing_key = SigningKey::from_bytes(&signing_key_array);
    signing_key_bytes.zeroize();
    let executor = IncidentExecutor::new(
        store,
        effects,
        required_identifier("AGENT_TRUST_INCIDENT_RELEASE_SIGNING_KEY_ID")?,
        signing_key,
        required_i64("AGENT_TRUST_INCIDENT_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;
    let allowed_identities = required_identities("AGENT_TRUST_INCIDENT_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(IncidentTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_INCIDENT_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let audience = required_identifier("AGENT_TRUST_INCIDENT_HUMAN_PRINCIPAL_AUDIENCE")?;
    let keyring_bytes = std::fs::read(required_path(
        "AGENT_TRUST_INCIDENT_HUMAN_PRINCIPAL_KEYRING_FILE",
    )?)?;
    let keyring = Arc::new(HumanPrincipalKeyring::from_json(
        &keyring_bytes,
        &audience,
        chrono::Utc::now(),
    )?);
    let service_subject = required_identifier("AGENT_TRUST_INCIDENT_SERVICE_SUBJECT")?;
    let authentication_age = required_i64(
        "AGENT_TRUST_INCIDENT_MAXIMUM_AUTHENTICATION_AGE_SECONDS",
        60,
        86_400,
    )?;
    let application = router(
        authority.clone(),
        executor.clone(),
        tokens,
        keyring,
        service_subject.clone(),
        authentication_age,
    );
    let data_address: IpAddr = env::var("AGENT_TRUST_INCIDENT_LISTEN_ADDRESS")?.parse()?;
    let data_port = required_i64("AGENT_TRUST_INCIDENT_PORT", 1, 65_535)? as u16;
    let management_address: IpAddr =
        env::var("AGENT_TRUST_INCIDENT_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    let management_port = required_i64("AGENT_TRUST_INCIDENT_MANAGEMENT_PORT", 1, 65_535)? as u16;
    serve(
        IncidentServerConfig {
            data_address: SocketAddr::new(data_address, data_port),
            management_address: SocketAddr::new(management_address, management_port),
            tls_ca_file: required_path("AGENT_TRUST_INCIDENT_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_INCIDENT_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_INCIDENT_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: allowed_identities,
            service_subject,
            maximum_authentication_age_seconds: authentication_age,
        },
        application,
        authority,
        executor,
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
        return Err("INCIDENT_DATABASE_ROLE_UNSAFE".into());
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
            return Err("INCIDENT_DATABASE_URL_INVALID".into());
        }
    }
    let database = parsed.path().strip_prefix('/').unwrap_or("");
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || database.is_empty()
        || database.len() > 63
        || database.contains('/')
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
        return Err("INCIDENT_DATABASE_URL_INVALID".into());
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
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, false)? {
        return Err("INCIDENT_REQUIRED_FILE_INVALID".into());
    }
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, true)? {
        return Err("INCIDENT_PRIVATE_FILE_INVALID".into());
    }
    Ok(path)
}

fn secure_file(path: &Path, private: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let effective_gid = nix::unistd::Gid::effective().as_raw();
    let access = if private {
        let allowed = 0o400
            | if metadata.gid() == effective_gid {
                0o040
            } else {
                0
            };
        let readable = (metadata.uid() == effective_uid && mode & 0o400 != 0)
            || (metadata.gid() == effective_gid && mode & 0o040 != 0);
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
        return Err("INCIDENT_SECRET_FILE_INVALID".into());
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
        return Err("INCIDENT_BINARY_SECRET_INVALID".into());
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
        return Err("INCIDENT_ENDPOINT_INVALID".into());
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
        return Err("INCIDENT_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if !uuid::Uuid::parse_str(&value).is_ok_and(|parsed| parsed.to_string() == value) {
        return Err("INCIDENT_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value: i64 = env::var(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("INCIDENT_INTEGER_INVALID".into());
    }
    Ok(value)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let values = env::var(name)?;
    let parsed = values
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if parsed.is_empty()
        || parsed.len() > 64
        || parsed.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err("INCIDENT_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_files_accept_csi_group_read_but_reject_other_access() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "agenttrust-incident-private-file-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::write(&path, b"secret")
            .unwrap_or_else(|error| panic!("create private-file fixture: {error}"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o440))
            .unwrap_or_else(|error| panic!("set CSI fixture mode: {error}"));
        assert!(secure_file(&path, true).unwrap_or(false));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .unwrap_or_else(|error| panic!("set unsafe fixture mode: {error}"));
        assert!(!secure_file(&path, true).unwrap_or(true));
        std::fs::remove_file(path)
            .unwrap_or_else(|error| panic!("remove private-file fixture: {error}"));
    }

    #[test]
    fn database_url_is_exact_and_has_no_path_escape() {
        let ca = Path::new("/var/run/incident/db-ca.pem");
        let valid = "postgresql://incident_authority_application_role@db.internal/agentsphere?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic";
        assert!(
            database_options(
                valid,
                "not-a-real-secret",
                ca,
                "incident_authority_application_role"
            )
            .is_ok()
        );
        assert!(
            database_options(
                &valid.replace("sslmode", "SSLMODE"),
                "not-a-real-secret",
                ca,
                "incident_authority_application_role"
            )
            .is_err()
        );
        assert!(
            database_options(
                &valid.replace("/agentsphere?", "/agentsphere/extra?"),
                "not-a-real-secret",
                ca,
                "incident_authority_application_role"
            )
            .is_err()
        );
    }
}
