use agent_trust_registry::server::{RegistryServerConfig, TokenBindingRegistryAuthorizer, serve};
use agent_trust_registry::{PostgresRegistryStore, RegistryApiState, RegistryPublisherSigner};
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
    let database_url = read_secret("AGENT_TRUST_REGISTRY_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_REGISTRY_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_REGISTRY_DATABASE_CA_FILE", false)?;
    let expected_role = required_env("AGENT_TRUST_REGISTRY_DATABASE_EXPECTED_ROLE")?;
    let connect = validate_database_url(&database_url, &database_ca, &database_password)?;
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .connect_with(connect)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;

    let publisher_key = read_signing_key("AGENT_TRUST_REGISTRY_PUBLISHER_PRIVATE_KEY_FILE")?;
    let signer = RegistryPublisherSigner::new(
        required_identifier("AGENT_TRUST_REGISTRY_PUBLISHER_ID")?,
        required_identifier("AGENT_TRUST_REGISTRY_PUBLISHER_KEY_ID")?,
        publisher_key,
    )?;
    let registry = Arc::new(PostgresRegistryStore::with_signer(pool, signer));
    let identities = parse_identities(&required_env("AGENT_TRUST_REGISTRY_CLIENT_IDENTITIES")?)?;
    let token_bindings = required_file("AGENT_TRUST_REGISTRY_TOKEN_BINDINGS_FILE", true)?;
    let authorizer = Arc::new(TokenBindingRegistryAuthorizer::from_file(
        &token_bindings,
        &identities,
    )?);
    let tenants = authorizer.tenants().clone();
    if !registry.ready().await {
        return Err("REGISTRY_DATABASE_NOT_READY".into());
    }
    for tenant in &tenants {
        if !registry.publisher_ready(tenant).await {
            return Err("REGISTRY_PUBLISHER_NOT_READY".into());
        }
    }
    let api_state = RegistryApiState::production(registry.clone(), authorizer)?;
    serve(
        RegistryServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_REGISTRY_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file(
                "AGENT_TRUST_REGISTRY_TLS_CERTIFICATE_FILE",
                false,
            )?,
            tls_private_key_file: required_file("AGENT_TRUST_REGISTRY_TLS_PRIVATE_KEY_FILE", true)?,
            client_identities: identities,
        },
        api_state,
        registry,
        tenants,
    )
    .await?;
    Ok(())
}

fn validate_database_url(
    value: &str,
    ca_file: &Path,
    password: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let query = parsed.query_pairs().collect::<Vec<_>>();
    let mut normalized = std::collections::BTreeMap::new();
    for (key, value) in &query {
        let normalized_key = key.to_ascii_lowercase();
        if key.as_ref() != normalized_key
            || value.is_empty()
            || normalized.insert(normalized_key, value.as_ref()).is_some()
        {
            return Err("REGISTRY_DATABASE_URL_INVALID".into());
        }
    }
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path().trim_matches('/').is_empty()
        || parsed.path().trim_matches('/').contains('/')
        || parsed.fragment().is_some()
        || normalized.len() != 2
        || normalized.get("sslmode") != Some(&"verify-full")
        || normalized.get("options") != Some(&"-csearch_path=pg_catalog,public")
        || !ca_file.is_absolute()
        || password.is_empty()
        || password.len() > 65_536
    {
        return Err("REGISTRY_DATABASE_URL_INVALID".into());
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
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,rolreplication, \
         current_setting('search_path') AS search_path,current_schemas(false)::text AS resolved_schemas, \
         current_setting('row_security') AS row_security, \
         has_schema_privilege(current_user,'public','CREATE') AS can_create \
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
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("REGISTRY_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8084_u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9094_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("REGISTRY_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("REGISTRY_ARGUMENTS_INVALID".into()),
        }
    }
    if port == 0 || management_port == 0 || port == management_port {
        return Err("REGISTRY_ARGUMENTS_INVALID".into());
    }
    Ok(Arguments {
        data: format!("{listen}:{port}").parse()?,
        management: format!("{management_listen}:{management_port}").parse()?,
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
        .decode(encoded)
        .map_err(|_| format!("{name}_INVALID"))?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name}_INVALID"))?;
    Ok(SigningKey::from_bytes(&bytes))
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
    if values.is_empty() || values.iter().any(|value| value.is_empty()) {
        return Err("REGISTRY_CLIENT_IDENTITIES_INVALID".into());
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
fn secure_file(path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1_048_576)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_defaults_are_distinct() {
        let arguments = parse_args(Vec::new()).unwrap_or_else(|error| panic!("defaults: {error}"));
        assert_eq!(arguments.data.port(), 8084);
        assert_eq!(arguments.management.port(), 9094);
        assert!(parse_args(["--management-port".into(), "8084".into()]).is_err());
    }

    #[test]
    fn database_url_cannot_carry_credentials_or_unpinned_options() {
        let ca = Path::new("/var/run/agenttrust/database-ca.pem");
        let valid = "postgresql://registry@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic";
        assert!(validate_database_url(valid, ca, "separate-secret").is_ok());
        assert!(validate_database_url(
            "postgresql://registry:embedded@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic",
            ca,
            "separate-secret"
        )
        .is_err());
        assert!(validate_database_url(
            "postgresql://registry@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic&password=embedded",
            ca,
            "separate-secret"
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_file_group_read_requires_effective_group() {
        assert!(private_file_access_allowed(0o400, 1000, 2000, 1000, 3000));
        assert!(private_file_access_allowed(0o440, 999, 2000, 1000, 2000));
        assert!(!private_file_access_allowed(0o440, 1000, 2000, 1000, 3000));
        assert!(!private_file_access_allowed(0o600, 1000, 2000, 1000, 2000));
        assert!(!private_file_access_allowed(0o404, 1000, 2000, 1000, 2000));
    }
}
