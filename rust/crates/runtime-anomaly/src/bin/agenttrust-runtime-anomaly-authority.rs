use agent_trust_contracts::{AgentInstanceId, ToolId, ToolVersion};
use agent_trust_runtime_anomaly::ContinuousAuthorizationController;
use agent_trust_runtime_anomaly::authority::{
    PostgresRuntimeAnomalyStore, RuntimeAnomalyAuthority, RuntimeAnomalyAuthorityConfig,
    RuntimeAnomalyExecutor,
};
use agent_trust_runtime_anomaly::production::{
    HttpsRuntimeAnomalyRuntime, RuntimeAnomalyDependencyConfig, RuntimeAnomalyEndpoint,
    RuntimeAnomalyEvidenceKeyring,
};
use agent_trust_runtime_anomaly::server::{
    RuntimeAnomalyServerConfig, RuntimeAnomalyTokenAuthorizer, data_router, management_router,
    serve,
};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
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
        eprintln!("RUNTIME_ANOMALY_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if nix::unistd::Uid::effective().is_root() {
        return Err("RUNTIME_ANOMALY_ROOT_EXECUTION_DENIED".into());
    }
    let database_url =
        read_secret_file("AGENT_TRUST_RUNTIME_ANOMALY_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password = read_secret_file(
        "AGENT_TRUST_RUNTIME_ANOMALY_DATABASE_PASSWORD_FILE",
        16,
        8_192,
    )?;
    let expected_role = required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_public_path("AGENT_TRUST_RUNTIME_ANOMALY_DATABASE_CA_FILE")?;
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
            "AGENT_TRUST_RUNTIME_ANOMALY_DATABASE_MAX_CONNECTIONS",
            2,
            100,
        )?)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound_ca = required_public_path("AGENT_TRUST_RUNTIME_ANOMALY_OUTBOUND_CA_FILE")?;
    let outbound_certificate =
        required_public_path("AGENT_TRUST_RUNTIME_ANOMALY_OUTBOUND_CERTIFICATE_FILE")?;
    let outbound_private_key =
        required_private_path("AGENT_TRUST_RUNTIME_ANOMALY_OUTBOUND_PRIVATE_KEY_FILE")?;
    let dependencies = RuntimeAnomalyDependencyConfig {
        orchestrator: required_endpoint("ORCHESTRATOR")?,
        supervisor: required_endpoint("SUPERVISOR")?,
        credential_authority: required_endpoint("CREDENTIAL_AUTHORITY")?,
        incident_authority: required_endpoint("INCIDENT_AUTHORITY")?,
        evidence_authority: required_endpoint("EVIDENCE_AUTHORITY")?,
        evidence_client_identity: required_identifier(
            "AGENT_TRUST_RUNTIME_ANOMALY_EVIDENCE_CLIENT_IDENTITY",
        )?,
        evidence_keyring: RuntimeAnomalyEvidenceKeyring::from_json(&std::fs::read(
            required_public_path("AGENT_TRUST_RUNTIME_ANOMALY_EVIDENCE_KEYRING_FILE")?,
        )?)?,
        maximum_response_bytes: required_usize(
            "AGENT_TRUST_RUNTIME_ANOMALY_MAXIMUM_RESPONSE_BYTES",
            4_096,
            4_194_304,
        )?,
    };
    validate_distinct_tokens(&dependencies)?;
    let runtime = Arc::new(HttpsRuntimeAnomalyRuntime::new(
        &outbound_ca,
        &outbound_certificate,
        &outbound_private_key,
        dependencies,
    )?);

    let mut response_key_bytes = read_binary_secret(
        "AGENT_TRUST_RUNTIME_ANOMALY_RESPONSE_SIGNING_KEY_FILE",
        32,
        32,
    )?;
    let mut response_key_array: [u8; 32] = response_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "RUNTIME_ANOMALY_RESPONSE_SIGNING_KEY_INVALID")?;
    let signing_key = SigningKey::from_bytes(&response_key_array);
    response_key_array.zeroize();
    response_key_bytes.zeroize();
    let response_controller = Arc::new(ContinuousAuthorizationController::new(
        required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_RESPONSE_ISSUER")?,
        required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_RESPONSE_KEY_ID")?,
        signing_key.clone(),
    )?);

    let store = PostgresRuntimeAnomalyStore::new(pool);
    let authority = RuntimeAnomalyAuthority::new(
        store.clone(),
        runtime.clone(),
        runtime.clone(),
        RuntimeAnomalyAuthorityConfig {
            service_agent_id: AgentInstanceId(
                required_uuid("AGENT_TRUST_RUNTIME_ANOMALY_AGENT_INSTANCE_ID")?.to_string(),
            ),
            organization_id: required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier(
                "AGENT_TRUST_RUNTIME_ANOMALY_TOOL_VERSION",
            )?),
            credential_profile: required_identifier(
                "AGENT_TRUST_RUNTIME_ANOMALY_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_SERVICE_SUBJECT")?,
            rule_version: required_identifier("AGENT_TRUST_RUNTIME_ANOMALY_RULE_VERSION")?,
            rule_bundle_digest: required_digest("AGENT_TRUST_RUNTIME_ANOMALY_RULE_BUNDLE_DIGEST")?,
            maximum_signal_clock_skew_seconds: required_i64(
                "AGENT_TRUST_RUNTIME_ANOMALY_MAXIMUM_SIGNAL_CLOCK_SKEW_SECONDS",
                0,
                300,
            )?,
            maximum_signal_lookback: required_i64(
                "AGENT_TRUST_RUNTIME_ANOMALY_MAXIMUM_SIGNAL_LOOKBACK",
                10,
                4096,
            )?,
            slow_exfiltration_distinct_domains: required_usize(
                "AGENT_TRUST_RUNTIME_ANOMALY_SLOW_EXFILTRATION_DISTINCT_DOMAINS",
                2,
                256,
            )?,
            repeated_side_effect_limit: required_usize(
                "AGENT_TRUST_RUNTIME_ANOMALY_REPEATED_SIDE_EFFECT_LIMIT",
                2,
                256,
            )?,
        },
        response_controller,
    )?;
    let executor = RuntimeAnomalyExecutor::new(
        store,
        runtime,
        required_uuid("AGENT_TRUST_RUNTIME_ANOMALY_EXECUTION_OWNER")?,
        required_i64(
            "AGENT_TRUST_RUNTIME_ANOMALY_EXECUTION_LEASE_SECONDS",
            15,
            300,
        )?,
        signing_key.verifying_key(),
    )?;

    let identities = required_identities("AGENT_TRUST_RUNTIME_ANOMALY_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(RuntimeAnomalyTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_RUNTIME_ANOMALY_TOKEN_BINDINGS_FILE")?,
        &identities,
    )?);
    let recovery_tenants = tokens.tenants();
    let recovery_authority = authority.clone();
    let recovery_executor = executor.clone();
    let recovery_seconds = required_u64(
        "AGENT_TRUST_RUNTIME_ANOMALY_RECOVERY_INTERVAL_SECONDS",
        5,
        300,
    )?;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(recovery_seconds));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            for tenant in &recovery_tenants {
                let _ = recovery_authority.recover_signal_evidence(tenant, 25).await;
                let _ = recovery_executor.recover_pending_evidence(tenant, 25).await;
            }
        }
    });

    let maximum_concurrency =
        required_usize("AGENT_TRUST_RUNTIME_ANOMALY_MAXIMUM_CONCURRENCY", 1, 10_000)?;
    let data = data_router(
        authority.clone(),
        executor.clone(),
        tokens,
        maximum_concurrency,
    );
    let management = management_router(authority, executor);
    let data_ip: IpAddr = required_env("AGENT_TRUST_RUNTIME_ANOMALY_DATA_ADDRESS")?.parse()?;
    let management_ip: IpAddr =
        required_env("AGENT_TRUST_RUNTIME_ANOMALY_MANAGEMENT_ADDRESS")?.parse()?;
    serve(
        RuntimeAnomalyServerConfig {
            data_address: SocketAddr::new(
                data_ip,
                required_exact_port("AGENT_TRUST_RUNTIME_ANOMALY_DATA_PORT", 8_094)?,
            ),
            management_address: SocketAddr::new(
                management_ip,
                required_exact_port("AGENT_TRUST_RUNTIME_ANOMALY_MANAGEMENT_PORT", 9_104)?,
            ),
            tls_ca_file: required_public_path("AGENT_TRUST_RUNTIME_ANOMALY_TLS_CA_FILE")?,
            tls_certificate_file: required_public_path(
                "AGENT_TRUST_RUNTIME_ANOMALY_TLS_CERTIFICATE_FILE",
            )?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_RUNTIME_ANOMALY_TLS_PRIVATE_KEY_FILE",
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

fn required_endpoint(name: &str) -> Result<RuntimeAnomalyEndpoint, Box<dyn std::error::Error>> {
    let prefix = format!("AGENT_TRUST_RUNTIME_ANOMALY_{name}");
    Ok(RuntimeAnomalyEndpoint {
        origin: required_url(&format!("{prefix}_ENDPOINT"))?,
        token_file: required_private_path(&format!("{prefix}_TOKEN_FILE"))?,
        readiness_schema: required_identifier(&format!("{prefix}_READINESS_SCHEMA"))?,
    })
}

fn validate_distinct_tokens(
    dependencies: &RuntimeAnomalyDependencyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let paths = [
        &dependencies.orchestrator.token_file,
        &dependencies.supervisor.token_file,
        &dependencies.credential_authority.token_file,
        &dependencies.incident_authority.token_file,
        &dependencies.evidence_authority.token_file,
    ];
    if paths.iter().collect::<BTreeSet<_>>().len() != paths.len() {
        return Err("RUNTIME_ANOMALY_TOKEN_PATH_REUSE_DENIED".into());
    }
    let mut digests = BTreeSet::new();
    for path in paths {
        let mut value = std::fs::read(path)?;
        let digest = hex::encode(Sha256::digest(&value));
        value.zeroize();
        if !digests.insert(digest) {
            return Err("RUNTIME_ANOMALY_TOKEN_VALUE_REUSE_DENIED".into());
        }
    }
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
        return Err("RUNTIME_ANOMALY_DATABASE_URL_INVALID".into());
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
        "SELECT current_user role_name,r.rolsuper,r.rolbypassrls,r.rolinherit,r.rolreplication,\
                r.rolcreaterole,r.rolcreatedb FROM pg_roles r WHERE r.rolname=current_user",
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
        return Err("RUNTIME_ANOMALY_DATABASE_ROLE_UNSAFE".into());
    }
    let row_security: String = sqlx::query_scalar("SHOW row_security")
        .fetch_one(pool)
        .await?;
    if row_security != "on" {
        return Err("RUNTIME_ANOMALY_DATABASE_RLS_DISABLED".into());
    }
    let tables = expected_tables();
    let rls_rows = sqlx::query(
        "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c \
         JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname='public' AND c.relname=ANY($1)",
    )
    .bind(tables.iter().cloned().collect::<Vec<_>>())
    .fetch_all(pool)
    .await?;
    if rls_rows.len() != tables.len()
        || rls_rows.iter().any(|item| {
            !item.get::<bool, _>("relrowsecurity") || !item.get::<bool, _>("relforcerowsecurity")
        })
    {
        return Err("RUNTIME_ANOMALY_DATABASE_RLS_POSTURE_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_DATABASE_GRANTS_INVALID".into());
    }
    let routine_grants = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM information_schema.role_routine_grants \
         WHERE grantee=$1 AND routine_schema='public'",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    let privilege_row = sqlx::query(
        "SELECT has_schema_privilege($1,'public','CREATE') schema_create,\
                has_database_privilege($1,current_database(),'TEMP') database_temp",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if routine_grants != 0
        || privilege_row.get::<bool, _>("schema_create")
        || privilege_row.get::<bool, _>("database_temp")
    {
        return Err("RUNTIME_ANOMALY_DATABASE_ROLE_EXCESS_PRIVILEGE".into());
    }
    Ok(())
}

fn expected_tables() -> BTreeSet<String> {
    [
        "runtime_anomaly_signal_sources",
        "runtime_anomaly_trajectories",
        "runtime_anomaly_signals",
        "runtime_anomaly_findings",
        "runtime_anomaly_aggregates",
        "runtime_anomaly_baselines",
        "runtime_anomaly_feedback",
        "runtime_anomaly_cases",
        "runtime_anomaly_action_ingress",
        "runtime_anomaly_authority_executions",
        "runtime_anomaly_response_commands",
        "runtime_anomaly_evidence_events",
        "runtime_anomaly_evidence_outbox",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn expected_grants() -> BTreeSet<String> {
    let mutable = BTreeSet::from([
        "runtime_anomaly_signal_sources",
        "runtime_anomaly_trajectories",
        "runtime_anomaly_cases",
        "runtime_anomaly_action_ingress",
        "runtime_anomaly_authority_executions",
        "runtime_anomaly_response_commands",
        "runtime_anomaly_evidence_outbox",
    ]);
    let mut grants = BTreeSet::new();
    for table in expected_tables() {
        grants.insert(format!("{table}:INSERT"));
        grants.insert(format!("{table}:SELECT"));
        if mutable.contains(table.as_str()) {
            grants.insert(format!("{table}:UPDATE"));
        }
    }
    grants
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty() || value.len() > 16_384 || value.contains(['\0', '\r', '\n']) {
        return Err("RUNTIME_ANOMALY_ENV_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_digest(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err("RUNTIME_ANOMALY_DIGEST_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<Uuid, Box<dyn std::error::Error>> {
    let raw = required_env(name)?;
    let value = Uuid::parse_str(&raw)?;
    if value.is_nil() || value.to_string() != raw {
        return Err("RUNTIME_ANOMALY_UUID_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_URL_INVALID".into());
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
    let permitted = if private {
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
        || !permitted
    {
        return Err("RUNTIME_ANOMALY_FILE_POSTURE_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_SECRET_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_BINARY_SECRET_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

fn required_exact_port(name: &str, expected: u16) -> Result<u16, Box<dyn std::error::Error>> {
    let value: u16 = required_env(name)?.parse()?;
    if value != expected {
        return Err("RUNTIME_ANOMALY_PORT_INVALID".into());
    }
    Ok(value)
}

fn required_u32(name: &str, minimum: u32, maximum: u32) -> Result<u32, Box<dyn std::error::Error>> {
    let value: u32 = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("RUNTIME_ANOMALY_NUMBER_INVALID".into());
    }
    Ok(value)
}

fn required_u64(name: &str, minimum: u64, maximum: u64) -> Result<u64, Box<dyn std::error::Error>> {
    let value: u64 = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("RUNTIME_ANOMALY_NUMBER_INVALID".into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value: i64 = required_env(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("RUNTIME_ANOMALY_NUMBER_INVALID".into());
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
        return Err("RUNTIME_ANOMALY_NUMBER_INVALID".into());
    }
    Ok(value)
}
