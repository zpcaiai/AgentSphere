use agent_trust_contracts::{AgentInstanceId, ToolId, ToolVersion};
use agent_trust_security_evaluation_lab::authority::{
    DatasetTrustKeyring, PostgresSecurityEvalStore, SecurityEvalAuthorityConfig,
    SecurityEvalExecutor, SecurityEvalIngressAuthority,
};
use agent_trust_security_evaluation_lab::server::{
    HttpIsolatedRunner, HttpSecurityEvalEvidence, HttpSecurityEvalOrchestrator,
    SecurityEvalEvidenceKeyring, SecurityEvalServerConfig, SecurityEvalTokenAuthorizer,
    data_router, management_router, serve,
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
use uuid::Uuid;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("SECURITY_EVALUATION_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if nix::unistd::Uid::effective().is_root() {
        return Err("SECURITY_EVAL_ROOT_EXECUTION_DENIED".into());
    }
    let database_url = read_secret_file("AGENT_TRUST_SECURITY_EVAL_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password = read_secret_file(
        "AGENT_TRUST_SECURITY_EVAL_DATABASE_PASSWORD_FILE",
        16,
        8_192,
    )?;
    let expected_role = required_identifier("AGENT_TRUST_SECURITY_EVAL_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_public_path("AGENT_TRUST_SECURITY_EVAL_DATABASE_CA_FILE")?;
    let options = database_options(
        &database_url,
        &database_password,
        &database_ca,
        &expected_role,
    )?;
    database_password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(required_u32(
            "AGENT_TRUST_SECURITY_EVAL_DATABASE_MAX_CONNECTIONS",
            2,
            100,
        )?)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_public_path("AGENT_TRUST_SECURITY_EVAL_OUTBOUND_CA_FILE")?,
        &required_public_path("AGENT_TRUST_SECURITY_EVAL_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_SECURITY_EVAL_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let store = PostgresSecurityEvalStore::new(pool);
    let orchestrator = Arc::new(HttpSecurityEvalOrchestrator::new(
        outbound.clone(),
        required_url("AGENT_TRUST_SECURITY_EVAL_ORCHESTRATOR_ENDPOINT")?,
        required_private_path("AGENT_TRUST_SECURITY_EVAL_ORCHESTRATOR_TOKEN_FILE")?,
    )?);
    let ingress = SecurityEvalIngressAuthority::new(
        store.clone(),
        orchestrator,
        SecurityEvalAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_SECURITY_EVAL_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_SECURITY_EVAL_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_SECURITY_EVAL_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_SECURITY_EVAL_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_SECURITY_EVAL_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier(
                "AGENT_TRUST_SECURITY_EVAL_TOOL_VERSION",
            )?),
            credential_profile: required_identifier(
                "AGENT_TRUST_SECURITY_EVAL_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: required_identifier("AGENT_TRUST_SECURITY_EVAL_SERVICE_SUBJECT")?,
        },
    )?;
    let runner = Arc::new(HttpIsolatedRunner::new(
        outbound.clone(),
        required_url("AGENT_TRUST_SECURITY_EVAL_ISOLATED_RUNNER_ENDPOINT")?,
        required_private_path("AGENT_TRUST_SECURITY_EVAL_ISOLATED_RUNNER_TOKEN_FILE")?,
    )?);
    let evidence = Arc::new(HttpSecurityEvalEvidence::new(
        outbound,
        required_url("AGENT_TRUST_SECURITY_EVAL_EVIDENCE_ENDPOINT")?,
        required_private_path("AGENT_TRUST_SECURITY_EVAL_EVIDENCE_TOKEN_FILE")?,
        required_identifier("AGENT_TRUST_SECURITY_EVAL_EVIDENCE_CLIENT_IDENTITY")?,
        SecurityEvalEvidenceKeyring::from_json(&std::fs::read(required_public_path(
            "AGENT_TRUST_SECURITY_EVAL_EVIDENCE_KEYRING_FILE",
        )?)?)?,
    )?);
    let keyring_path = required_private_path("AGENT_TRUST_SECURITY_EVAL_DATASET_KEYRING_FILE")?;
    let keyring_bytes = std::fs::read(&keyring_path)?;
    let dataset_keys = DatasetTrustKeyring::from_json(&keyring_bytes, chrono::Utc::now())?;
    let mut signing_key_bytes =
        read_binary_secret("AGENT_TRUST_SECURITY_EVAL_REPORT_SIGNING_KEY_FILE", 32, 32)?;
    let signing_key_array: [u8; 32] = signing_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "SECURITY_EVAL_REPORT_SIGNING_KEY_INVALID")?;
    let report_signer = SigningKey::from_bytes(&signing_key_array);
    signing_key_bytes.zeroize();
    let executor = SecurityEvalExecutor::new(
        store,
        runner,
        evidence,
        dataset_keys,
        required_identifier("AGENT_TRUST_SECURITY_EVAL_REPORT_SIGNING_KEY_ID")?,
        report_signer,
        required_i64("AGENT_TRUST_SECURITY_EVAL_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;
    let identities = required_identities("AGENT_TRUST_SECURITY_EVAL_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(SecurityEvalTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_SECURITY_EVAL_TOKEN_BINDINGS_FILE")?,
        &identities,
    )?);
    let maximum_concurrency =
        required_usize("AGENT_TRUST_SECURITY_EVAL_MAXIMUM_CONCURRENCY", 1, 10_000)?;
    let data = data_router(
        ingress.clone(),
        executor.clone(),
        tokens.clone(),
        maximum_concurrency,
    );
    let management = management_router(ingress, executor);
    let data_ip: IpAddr = required_env("AGENT_TRUST_SECURITY_EVAL_DATA_ADDRESS")?.parse()?;
    let management_ip: IpAddr =
        required_env("AGENT_TRUST_SECURITY_EVAL_MANAGEMENT_ADDRESS")?.parse()?;
    serve(
        SecurityEvalServerConfig {
            data_address: SocketAddr::new(
                data_ip,
                required_u16("AGENT_TRUST_SECURITY_EVAL_DATA_PORT", 8_096, 8_096)?,
            ),
            management_address: SocketAddr::new(
                management_ip,
                required_u16("AGENT_TRUST_SECURITY_EVAL_MANAGEMENT_PORT", 9_106, 9_106)?,
            ),
            tls_ca_file: required_public_path("AGENT_TRUST_SECURITY_EVAL_TLS_CA_FILE")?,
            tls_certificate_file: required_public_path(
                "AGENT_TRUST_SECURITY_EVAL_TLS_CERTIFICATE_FILE",
            )?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_SECURITY_EVAL_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: identities,
            maximum_concurrency,
        },
        data,
        management,
    )
    .await?;
    Ok(())
}

fn database_options(
    database_url: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(database_url)?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.password().is_some()
        || parsed.username() != expected_role
        || parsed.fragment().is_some()
    {
        return Err("SECURITY_EVAL_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::from_str(database_url)?
        .password(password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file))
}

async fn verify_database_role(
    pool: &sqlx::PgPool,
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,r.rolsuper,r.rolbypassrls,r.rolinherit,r.rolreplication,\
                r.rolcreaterole,r.rolcreatedb \
         FROM pg_roles r WHERE r.rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
    if row.get::<String, _>("role_name") != expected_role
        || row.get::<bool, _>("rolsuper")
        || row.get::<bool, _>("rolbypassrls")
        || row.get::<bool, _>("rolinherit")
        || row.get::<bool, _>("rolreplication")
        || row.get::<bool, _>("rolcreaterole")
        || row.get::<bool, _>("rolcreatedb")
    {
        return Err("SECURITY_EVAL_DATABASE_ROLE_UNSAFE".into());
    }
    let row_security: String = sqlx::query_scalar("SHOW row_security")
        .fetch_one(pool)
        .await?;
    if row_security != "on" {
        return Err("SECURITY_EVAL_DATABASE_RLS_DISABLED".into());
    }
    let rls_rows = sqlx::query(
        "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity \
         FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname='public' AND c.relname=ANY($1)",
    )
    .bind(expected_tables().into_iter().collect::<Vec<_>>())
    .fetch_all(pool)
    .await?;
    if rls_rows.len() != expected_tables().len()
        || rls_rows.iter().any(|item| {
            !item.get::<bool, _>("relrowsecurity") || !item.get::<bool, _>("relforcerowsecurity")
        })
    {
        return Err("SECURITY_EVAL_DATABASE_RLS_POSTURE_INVALID".into());
    }
    let grants = sqlx::query(
        "SELECT table_name,privilege_type FROM information_schema.role_table_grants \
         WHERE grantee=$1 AND table_schema='public'",
    )
    .bind(expected_role)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| {
        format!(
            "{}:{}",
            row.get::<String, _>("table_name"),
            row.get::<String, _>("privilege_type")
        )
    })
    .collect::<BTreeSet<_>>();
    if grants != expected_grants() {
        return Err("SECURITY_EVAL_DATABASE_GRANTS_INVALID".into());
    }
    let routine_grants = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM information_schema.role_routine_grants \
         WHERE grantee=$1 AND routine_schema='public'",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    let privilege_row = sqlx::query(
        "SELECT has_schema_privilege($1,'public','CREATE') AS schema_create,\
                has_database_privilege($1,current_database(),'TEMP') AS database_temp",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if routine_grants != 0
        || privilege_row.get::<bool, _>("schema_create")
        || privilege_row.get::<bool, _>("database_temp")
    {
        return Err("SECURITY_EVAL_DATABASE_ROLE_EXCESS_PRIVILEGE".into());
    }
    Ok(())
}

fn expected_tables() -> BTreeSet<String> {
    [
        "security_eval_datasets",
        "security_eval_dataset_versions",
        "attack_scenarios",
        "security_campaigns",
        "security_eval_campaign_scenarios",
        "security_eval_scenario_results",
        "security_findings",
        "security_eval_remediations",
        "security_eval_retests",
        "security_eval_baselines",
        "security_eval_reports",
        "security_eval_kill_switches",
        "security_eval_resource_versions",
        "security_eval_action_ingress",
        "security_eval_authority_executions",
        "security_eval_evidence_events",
        "security_eval_evidence_outbox",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn expected_grants() -> BTreeSet<String> {
    let mutable = BTreeSet::from([
        "security_eval_datasets",
        "security_campaigns",
        "security_findings",
        "security_eval_remediations",
        "security_eval_kill_switches",
        "security_eval_resource_versions",
        "security_eval_action_ingress",
        "security_eval_authority_executions",
        "security_eval_evidence_outbox",
    ]);
    let evidence_only = BTreeSet::from(["security_eval_evidence_events"]);
    let mut grants = BTreeSet::new();
    for table in expected_tables() {
        grants.insert(format!("{table}:INSERT"));
        if !evidence_only.contains(table.as_str()) {
            grants.insert(format!("{table}:SELECT"));
        }
        if mutable.contains(table.as_str()) {
            grants.insert(format!("{table}:UPDATE"));
        }
    }
    grants
}

fn outbound_client(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let ca = std::fs::read(ca_file)?;
    let certificate = Certificate::from_pem(&ca)?;
    let mut identity = std::fs::read(certificate_file)?;
    identity.extend_from_slice(&std::fs::read(private_key_file)?);
    let identity = Identity::from_pem(&identity)?;
    Ok(reqwest::Client::builder()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .identity(identity)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty() || value.len() > 16_384 || value.contains(['\0', '\r', '\n']) {
        return Err("SECURITY_EVAL_ENV_INVALID".into());
    }
    Ok(value)
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        })
    {
        return Err("SECURITY_EVAL_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<Uuid, Box<dyn std::error::Error>> {
    let raw = required_env(name)?;
    let value = Uuid::parse_str(&raw)?;
    if value.is_nil() || value.to_string() != raw {
        return Err("SECURITY_EVAL_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_url(name: &str) -> Result<url::Url, Box<dyn std::error::Error>> {
    let value = url::Url::parse(&required_env(name)?)?;
    if value.scheme() != "https"
        || value.host_str().is_none()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
        || !value.username().is_empty()
        || value.password().is_some()
    {
        return Err("SECURITY_EVAL_URL_INVALID".into());
    }
    Ok(value)
}

fn required_public_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(required_env(name)?);
    validate_file(&path, false)?;
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(required_env(name)?);
    validate_file(&path, true)?;
    Ok(path)
}

fn validate_file(path: &Path, private: bool) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let effective_gid = nix::unistd::Gid::effective().as_raw();
    let mode = metadata.mode() & 0o777;
    let private_access = if private {
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
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 4_194_304
        || !private_access
    {
        return Err("SECURITY_EVAL_FILE_POSTURE_INVALID".into());
    }
    Ok(())
}

fn read_secret_file(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_private_path(name)?;
    let value = std::fs::read_to_string(path)?;
    let trimmed = value.trim_end_matches(['\r', '\n']);
    if !(minimum..=maximum).contains(&trimmed.len())
        || trimmed.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(trimmed.len()) > 2
    {
        return Err("SECURITY_EVAL_SECRET_INVALID".into());
    }
    Ok(trimmed.into())
}

fn read_binary_secret(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = required_private_path(name)?;
    let value = std::fs::read(path)?;
    if !(minimum..=maximum).contains(&value.len()) {
        return Err("SECURITY_EVAL_BINARY_SECRET_INVALID".into());
    }
    Ok(value)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let identities = required_env(name)?
        .split(',')
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if identities.is_empty()
        || identities.len() > 256
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.contains(char::is_whitespace)
        })
    {
        return Err("SECURITY_EVAL_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

fn required_u16(name: &str, minimum: u16, maximum: u16) -> Result<u16, Box<dyn std::error::Error>> {
    let value: u16 = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("SECURITY_EVAL_NUMBER_INVALID".into());
    }
    Ok(value)
}

fn required_u32(name: &str, minimum: u32, maximum: u32) -> Result<u32, Box<dyn std::error::Error>> {
    let value: u32 = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("SECURITY_EVAL_NUMBER_INVALID".into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value: i64 = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("SECURITY_EVAL_NUMBER_INVALID".into());
    }
    Ok(value)
}

fn required_usize(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let value: usize = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("SECURITY_EVAL_NUMBER_INVALID".into());
    }
    Ok(value)
}
