use agent_trust_production_runtime::execution::{
    ApprovalGrantKeyring, EvidenceEventKeyring, ExecutionCoordinator, HttpApprovalGrantPort,
    HttpExecutionPort, HttpPepExecutionPort, PepAuthorizationKeyring, PostgresActionMaterializer,
    PostgresActiveToolRegistry,
};
use agent_trust_production_runtime::execution_server::{
    ExecutionServerConfig, serve, validate_certificate_identity_file,
};
use agent_trust_transaction_ledger::PostgresExecutionLedger;
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
    let database_url = read_secret("AGENT_TRUST_EXECUTION_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_EXECUTION_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_EXECUTION_DATABASE_CA_FILE", false)?;
    let expected_role = required_env("AGENT_TRUST_EXECUTION_DATABASE_EXPECTED_ROLE")?;
    let connect = validate_database_url(
        &database_url,
        &database_password,
        &database_ca,
        &expected_role,
    )?;
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .connect_with(connect)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;

    let client_ca = required_file("AGENT_TRUST_EXECUTION_CLIENT_CA_FILE", false)?;
    let client_certificate = required_file("AGENT_TRUST_EXECUTION_CLIENT_CERTIFICATE_FILE", false)?;
    let client_key = required_file("AGENT_TRUST_EXECUTION_CLIENT_PRIVATE_KEY_FILE", true)?;
    let outbound_client_identity = required_env("AGENT_TRUST_EXECUTION_OUTBOUND_CLIENT_IDENTITY")?;
    validate_certificate_identity_file(&client_certificate, &outbound_client_identity)?;
    let port_with_token = |name: &str,
                           token_file_env: &str,
                           evidence_keys|
     -> Result<HttpExecutionPort, Box<dyn std::error::Error>> {
        Ok(HttpExecutionPort::new(
            &required_env(&format!("AGENT_TRUST_EXECUTION_{name}_ENDPOINT"))?,
            read_secret(token_file_env)?,
            &client_ca,
            &client_certificate,
            &client_key,
            required_env(&format!("AGENT_TRUST_EXECUTION_{name}_READINESS_SCHEMA"))?,
            evidence_keys,
        )?)
    };
    let port =
        |name: &str, evidence_keys| -> Result<HttpExecutionPort, Box<dyn std::error::Error>> {
            port_with_token(
                name,
                &format!("AGENT_TRUST_EXECUTION_{name}_TOKEN_FILE"),
                evidence_keys,
            )
        };
    let pep_keys = PepAuthorizationKeyring::from_file(&required_file(
        "AGENT_TRUST_EXECUTION_PEP_VERIFICATION_KEYS_FILE",
        false,
    )?)?;
    let approval_keys = ApprovalGrantKeyring::from_file(&required_file(
        "AGENT_TRUST_EXECUTION_APPROVAL_VERIFICATION_KEYS_FILE",
        false,
    )?)?;
    let evidence_keys = EvidenceEventKeyring::from_file(&required_file(
        "AGENT_TRUST_EXECUTION_EVIDENCE_VERIFICATION_KEYS_FILE",
        false,
    )?)?;
    let pep = Arc::new(HttpPepExecutionPort::new(
        port_with_token(
            "PEP",
            "AGENT_TRUST_EXECUTION_PEP_PREAPPROVE_TOKEN_FILE",
            None,
        )?,
        port_with_token(
            "PEP",
            "AGENT_TRUST_EXECUTION_PEP_AUTHORIZE_TOKEN_FILE",
            None,
        )?,
        pep_keys,
    )?);
    let approval = Arc::new(HttpApprovalGrantPort::new(
        port("APPROVAL", None)?,
        approval_keys,
    ));
    let tool = Arc::new(port("TOOL", None)?);
    let evidence = Arc::new(port("EVIDENCE", Some(evidence_keys))?);
    let coordinator = Arc::new(ExecutionCoordinator::new(
        Arc::new(PostgresActionMaterializer::new(pool.clone())),
        Arc::new(PostgresActiveToolRegistry::new(pool.clone())),
        approval,
        pep,
        tool,
        evidence,
        Arc::new(PostgresExecutionLedger::new(pool)),
        outbound_client_identity,
    )?);
    serve(
        ExecutionServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_EXECUTION_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file(
                "AGENT_TRUST_EXECUTION_TLS_CERTIFICATE_FILE",
                false,
            )?,
            tls_private_key_file: required_file(
                "AGENT_TRUST_EXECUTION_TLS_PRIVATE_KEY_FILE",
                true,
            )?,
            client_identities: parse_identities(&required_env(
                "AGENT_TRUST_EXECUTION_CLIENT_IDENTITIES",
            )?)?,
            token_bindings_file: required_file("AGENT_TRUST_EXECUTION_TOKEN_BINDINGS_FILE", true)?,
        },
        coordinator,
    )
    .await?;
    Ok(())
}

fn validate_database_url(
    value: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let query = parsed.query_pairs().collect::<Vec<_>>();
    let mut normalized = std::collections::BTreeMap::new();
    for (key, value) in &query {
        let key = key.to_ascii_lowercase();
        if value.is_empty() || normalized.insert(key, value.as_ref()).is_some() {
            return Err("EXECUTION_DATABASE_URL_INVALID".into());
        }
    }
    let forbidden_tls = normalized
        .keys()
        .any(|key| key.starts_with("ssl") && key != "sslmode");
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || password.is_empty()
        || password.len() > 65_536
        || parsed.fragment().is_some()
        || normalized.get("sslmode") != Some(&"verify-full")
        || normalized.get("options") != Some(&"-csearch_path=pg_catalog,public")
        || forbidden_tls
        || !ca_file.is_absolute()
    {
        return Err("EXECUTION_DATABASE_URL_INVALID".into());
    }
    let options = PgConnectOptions::from_str(value)?
        .password(password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file);
    Ok(options)
}

async fn verify_database_posture(
    pool: &sqlx::PgPool,
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,current_setting('search_path') AS search_path, \
         current_schemas(false)::text AS resolved_schemas FROM pg_roles WHERE rolname=current_user",
    ).fetch_one(pool).await?;
    if row.try_get::<String, _>("role_name")? != expected_role
        || row.try_get::<bool, _>("rolsuper")?
        || row.try_get::<bool, _>("rolbypassrls")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
    {
        return Err("EXECUTION_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8083u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9093u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("EXECUTION_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("EXECUTION_ARGUMENTS_INVALID".into()),
        }
    }
    if port == 0 || management_port == 0 || port == management_port {
        return Err("EXECUTION_ARGUMENTS_INVALID".into());
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

fn read_secret(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    if std::fs::metadata(&path)?.len() > 65_536 {
        return Err(format!("{name}_INVALID").into());
    }
    let value = std::fs::read_to_string(path)?;
    let value = value.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value.to_string())
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
        return Err("EXECUTION_CLIENT_IDENTITIES_INVALID".into());
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
    let readable = (metadata.uid() == uid && mode & 0o400 != 0)
        || (metadata.gid() == gid && mode & 0o040 != 0);
    let access = if private {
        readable && mode & !0o440 == 0
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listeners_are_distinct() {
        let arguments = parse_args(Vec::new()).unwrap_or_else(|error| panic!("defaults: {error}"));
        assert_eq!(arguments.data.port(), 8083);
        assert_eq!(arguments.management.port(), 9093);
        assert!(parse_args(["--management-port".into(), "8083".into()]).is_err());
    }
}
