use agent_trust_contracts::{AgentInstanceId, HumanPrincipalKeyring, ToolId, ToolVersion};
use agent_trust_platform_sre::authority::{
    PostgresSreAuthorityStore, SreAuthorityConfig, SreExecutor, SreIngressAuthority,
};
use agent_trust_platform_sre::server::{
    HttpSreEffectPort, HttpSreOrchestrator, SreAdapterKind, SreAdapterTarget, SreServerConfig,
    SreEvidenceKeyring, SreTokenAuthorizer, router, serve,
};
use ed25519_dalek::SigningKey;
use reqwest::{Certificate, Identity};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::{BTreeMap, BTreeSet};
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
        eprintln!("PLATFORM_SRE_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = read_secret_file("AGENT_TRUST_SRE_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password =
        read_secret_file("AGENT_TRUST_SRE_DATABASE_PASSWORD_FILE", 16, 8_192)?;
    let expected_role = required_identifier("AGENT_TRUST_SRE_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_path("AGENT_TRUST_SRE_DATABASE_CA_FILE")?;
    let options = database_options(
        &database_url,
        &database_password,
        &database_ca,
        &expected_role,
    )?;
    database_password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(required_i64("AGENT_TRUST_SRE_DATABASE_MAX_CONNECTIONS", 2, 100)? as u32)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_SRE_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_SRE_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_SRE_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let orchestrator_endpoint = required_url("AGENT_TRUST_SRE_ORCHESTRATOR_ENDPOINT")?;
    let orchestrator_token = required_private_path("AGENT_TRUST_SRE_ORCHESTRATOR_TOKEN_FILE")?;
    let orchestrator = Arc::new(HttpSreOrchestrator::new(
        outbound.clone(),
        orchestrator_endpoint.clone(),
        orchestrator_token.clone(),
    )?);
    let targets = adapter_targets()?;
    verify_unique_dependency_credentials(&orchestrator_endpoint, &orchestrator_token, &targets)?;
    let effects = Arc::new(HttpSreEffectPort::new(
        outbound,
        targets,
        required_identifier("AGENT_TRUST_SRE_EVIDENCE_CLIENT_IDENTITY")?,
        SreEvidenceKeyring::from_json(&std::fs::read(required_path(
            "AGENT_TRUST_SRE_EVIDENCE_KEYRING_FILE",
        )?)?)?,
    )?);

    let store = PostgresSreAuthorityStore::new(pool);
    let ingress_subject = required_identifier("AGENT_TRUST_SRE_INGRESS_SUBJECT")?;
    let executor_subject = required_identifier("AGENT_TRUST_SRE_EXECUTOR_SUBJECT")?;
    let query_subject = required_identifier("AGENT_TRUST_SRE_QUERY_SUBJECT")?;
    if BTreeSet::from([
        ingress_subject.clone(),
        executor_subject.clone(),
        query_subject.clone(),
    ])
    .len()
        != 3
    {
        return Err("PLATFORM_SRE_SUBJECT_SEPARATION_REQUIRED".into());
    }
    let authority = SreIngressAuthority::new(
        store.clone(),
        orchestrator,
        SreAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_SRE_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_SRE_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_SRE_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_SRE_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_SRE_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_SRE_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_SRE_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: ingress_subject.clone(),
        },
    )?;
    let mut signing_key_bytes =
        read_binary_secret("AGENT_TRUST_SRE_REPORT_SIGNING_KEY_FILE", 32, 32)?;
    let signing_key_array: [u8; 32] = signing_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "PLATFORM_SRE_SIGNING_KEY_INVALID")?;
    let signing_key = SigningKey::from_bytes(&signing_key_array);
    signing_key_bytes.zeroize();
    let executor = SreExecutor::new(
        store,
        effects,
        required_identifier("AGENT_TRUST_SRE_REPORT_SIGNING_KEY_ID")?,
        signing_key,
        required_i64("AGENT_TRUST_SRE_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;

    let allowed_identities = required_identities("AGENT_TRUST_SRE_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(SreTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_SRE_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let audience = required_identifier("AGENT_TRUST_SRE_HUMAN_PRINCIPAL_AUDIENCE")?;
    let keyring_bytes =
        std::fs::read(required_path("AGENT_TRUST_SRE_HUMAN_PRINCIPAL_KEYRING_FILE")?)?;
    let keyring = Arc::new(HumanPrincipalKeyring::from_json(
        &keyring_bytes,
        &audience,
        chrono::Utc::now(),
    )?);
    let authentication_age = required_i64(
        "AGENT_TRUST_SRE_MAXIMUM_AUTHENTICATION_AGE_SECONDS",
        60,
        86_400,
    )?;
    let application = router(
        authority.clone(),
        executor.clone(),
        tokens,
        keyring,
        ingress_subject.clone(),
        executor_subject.clone(),
        query_subject.clone(),
        authentication_age,
    );
    let data_address: IpAddr = env::var("AGENT_TRUST_SRE_LISTEN_ADDRESS")?.parse()?;
    let data_port = required_i64("AGENT_TRUST_SRE_PORT", 8_097, 8_097)? as u16;
    let management_address: IpAddr =
        env::var("AGENT_TRUST_SRE_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    let management_port =
        required_i64("AGENT_TRUST_SRE_MANAGEMENT_PORT", 9_107, 9_107)? as u16;
    serve(
        SreServerConfig {
            data_address: SocketAddr::new(data_address, data_port),
            management_address: SocketAddr::new(management_address, management_port),
            tls_ca_file: required_path("AGENT_TRUST_SRE_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_SRE_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_SRE_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: allowed_identities,
            ingress_subject,
            executor_subject,
            query_subject,
            maximum_authentication_age_seconds: authentication_age,
        },
        application,
        authority,
        executor,
    )
    .await?;
    Ok(())
}

fn adapter_targets() -> Result<BTreeMap<SreAdapterKind, SreAdapterTarget>, Box<dyn std::error::Error>> {
    let definitions = [
        (SreAdapterKind::Backup, "BACKUP"),
        (SreAdapterKind::Recovery, "RECOVERY"),
        (SreAdapterKind::DisasterRecovery, "DR"),
        (SreAdapterKind::Chaos, "CHAOS"),
        (SreAdapterKind::Load, "LOAD"),
        (SreAdapterKind::Upgrade, "UPGRADE"),
        (SreAdapterKind::Evidence, "EVIDENCE"),
    ];
    definitions
        .into_iter()
        .map(|(kind, name)| {
            Ok((
                kind,
                SreAdapterTarget {
                    endpoint: required_url(&format!("AGENT_TRUST_SRE_{name}_ENDPOINT"))?,
                    token_file: required_private_path(&format!(
                        "AGENT_TRUST_SRE_{name}_TOKEN_FILE"
                    ))?,
                },
            ))
        })
        .collect()
}

fn verify_unique_dependency_credentials(
    orchestrator_endpoint: &url::Url,
    orchestrator_token: &Path,
    targets: &BTreeMap<SreAdapterKind, SreAdapterTarget>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut endpoints = BTreeSet::from([orchestrator_endpoint.as_str().to_string()]);
    let mut tokens = BTreeSet::from([sha256(read_secret_file_path(orchestrator_token, 16, 8_192)?.as_bytes())]);
    for target in targets.values() {
        if !endpoints.insert(target.endpoint.as_str().to_string())
            || !tokens.insert(sha256(
                read_secret_file_path(&target.token_file, 16, 8_192)?.as_bytes(),
            ))
        {
            return Err("PLATFORM_SRE_DEPENDENCY_CREDENTIAL_REUSE_DENIED".into());
        }
    }
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
        return Err("PLATFORM_SRE_DATABASE_ROLE_UNSAFE".into());
    }
    let expected_tables = BTreeSet::from([
        "sre_service_slos",
        "sre_sli_observations",
        "sre_burn_alerts",
        "sre_incident_links",
        "sre_deployment_topologies",
        "sre_zone_health_observations",
        "backup_manifests",
        "sre_backup_artifacts",
        "recovery_drills",
        "sre_dr_plans",
        "sre_dr_events",
        "sre_chaos_campaigns",
        "sre_chaos_results",
        "sre_load_campaigns",
        "sre_load_results",
        "deployment_rollouts",
        "sre_canary_observations",
        "sre_cost_capacity_observations",
        "sre_observability_evidence",
        "sre_resource_versions",
        "sre_action_ingress",
        "sre_principal_assertion_replay",
        "sre_authority_executions",
        "sre_evidence_outbox",
    ]);
    let grants = sqlx::query(
        "SELECT table_name,privilege_type FROM information_schema.role_table_grants \
         WHERE grantee=current_user AND table_schema='public'",
    )
    .fetch_all(pool)
    .await?;
    let mut by_table: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for grant in grants {
        let table: String = grant.try_get("table_name")?;
        let privilege: String = grant.try_get("privilege_type")?;
        if !expected_tables.contains(table.as_str()) {
            return Err("PLATFORM_SRE_DATABASE_CROSS_DOMAIN_GRANT".into());
        }
        by_table.entry(table).or_default().insert(privilege);
    }
    let expected_base = BTreeSet::from(["INSERT".to_string(), "SELECT".to_string()]);
    if by_table.len() != expected_tables.len()
        || expected_tables.iter().any(|table| {
            by_table.get(*table).is_none_or(|privileges| privileges != &expected_base)
        })
    {
        return Err("PLATFORM_SRE_DATABASE_TABLE_GRANTS_INVALID".into());
    }
    let expected_updates = expected_update_columns();
    let column_grants = sqlx::query(
        "SELECT table_name,column_name FROM information_schema.column_privileges \
         WHERE grantee=current_user AND table_schema='public' AND privilege_type='UPDATE'",
    )
    .fetch_all(pool)
    .await?;
    let observed_updates = column_grants
        .into_iter()
        .map(|row| Ok((row.try_get::<String, _>("table_name")?, row.try_get::<String, _>("column_name")?)))
        .collect::<Result<BTreeSet<_>, sqlx::Error>>()?;
    if observed_updates != expected_updates {
        return Err("PLATFORM_SRE_DATABASE_COLUMN_GRANTS_INVALID".into());
    }
    Ok(())
}

fn expected_update_columns() -> BTreeSet<(String, String)> {
    let values: &[(&str, &[&str])] = &[
        (
            "sre_service_slos",
            &[
                "service","sli_kind","window_seconds","target_millionths","minimum_samples",
                "fast_burn_threshold_millionths","slow_burn_threshold_millionths",
                "release_blocking","status","resource_version","updated_at",
            ],
        ),
        (
            "sre_deployment_topologies",
            &[
                "deployment_mode","release_digest","topology_digest","zones","components",
                "quorum_rules","disruption_budgets","immutable_image_digests","status",
                "resource_version","updated_at",
            ],
        ),
        (
            "sre_burn_alerts",
            &["state", "owner_subject", "resolved_at", "resource_version"],
        ),
        ("sre_dr_plans", &["status", "resource_version", "updated_at"]),
        ("sre_chaos_campaigns", &["status", "resource_version", "updated_at"]),
        ("sre_load_campaigns", &["status", "resource_version", "updated_at"]),
        (
            "deployment_rollouts",
            &["status", "current_canary_percent", "resource_version", "updated_at"],
        ),
        (
            "sre_resource_versions",
            &[
                "resource_version","action_hash","ledger_execution_id","ledger_event_id",
                "ledger_event_digest","fence_digest","updated_at",
            ],
        ),
        ("sre_action_ingress", &["state", "receipt", "updated_at"]),
        (
            "sre_authority_executions",
            &[
                "state","execution_owner","lease_expires_at","external_receipt","safe_result",
                "evidence_request","evidence_ref","evidence_digest","updated_at",
            ],
        ),
        (
            "sre_evidence_outbox",
            &["delivered_at", "delivery_attempts"],
        ),
    ];
    values
        .iter()
        .flat_map(|(table, columns)| {
            columns
                .iter()
                .map(|column| ((*table).to_string(), (*column).to_string()))
        })
        .collect()
}

fn database_options(
    value: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = url::Url::parse(value)?;
    let mut query = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized = key.to_ascii_lowercase();
        if key.as_ref() != normalized
            || value.is_empty()
            || query.insert(normalized, value.into_owned()).is_some()
        {
            return Err("PLATFORM_SRE_DATABASE_URL_INVALID".into());
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
        || query.get("options").map(String::as_str)
            != Some("-csearch_path=pg_catalog,public")
        || !ca_file.is_absolute()
    {
        return Err("PLATFORM_SRE_DATABASE_URL_INVALID".into());
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
        .timeout(std::time::Duration::from_secs(45))
        .pool_max_idle_per_host(8)
        .build()?)
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, false)? {
        return Err("PLATFORM_SRE_REQUIRED_FILE_INVALID".into());
    }
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, true)? {
        return Err("PLATFORM_SRE_PRIVATE_FILE_INVALID".into());
    }
    Ok(path)
}

fn secure_file(path: &Path, private: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.mode() & 0o777;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let effective_gid = nix::unistd::Gid::effective().as_raw();
    let access = if private {
        let allowed = 0o400 | if metadata.gid() == effective_gid { 0o040 } else { 0 };
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
    read_secret_file_path(&path, minimum, maximum)
}

fn read_secret_file_path(
    path: &Path,
    minimum: usize,
    maximum: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::fs::read_to_string(path)?;
    let secret = value.trim_end_matches(['\r', '\n']);
    if !(minimum..=maximum).contains(&secret.len())
        || secret.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(secret.len()) > 2
    {
        return Err("PLATFORM_SRE_SECRET_INVALID".into());
    }
    Ok(secret.to_string())
}

fn read_binary_secret(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value = std::fs::read(required_private_path(name)?)?;
    if !(minimum..=maximum).contains(&value.len()) {
        return Err("PLATFORM_SRE_BINARY_SECRET_INVALID".into());
    }
    Ok(value)
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty()
        || value.len() > 256
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || b"-_.:/@".contains(&byte))
        })
    {
        return Err("PLATFORM_SRE_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if !uuid::Uuid::parse_str(&value).is_ok_and(|parsed| parsed.to_string() == value) {
        return Err("PLATFORM_SRE_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_i64(
    name: &str,
    minimum: i64,
    maximum: i64,
) -> Result<i64, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    if raw.starts_with('+') || raw.starts_with('0') && raw.len() > 1 {
        return Err("PLATFORM_SRE_INTEGER_INVALID".into());
    }
    let value: i64 = raw.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("PLATFORM_SRE_INTEGER_INVALID".into());
    }
    Ok(value)
}

fn required_url(name: &str) -> Result<url::Url, Box<dyn std::error::Error>> {
    let value = url::Url::parse(&env::var(name)?)?;
    if value.scheme() != "https"
        || value.cannot_be_a_base()
        || value.host_str().is_none()
        || value.username() != ""
        || value.password().is_some()
        || value.query().is_some()
        || value.fragment().is_some()
        || value.path() != "/"
    {
        return Err("PLATFORM_SRE_URL_INVALID".into());
    }
    Ok(value)
}

fn required_identities(
    name: &str,
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let identities = raw.split(',').map(str::to_string).collect::<BTreeSet<_>>();
    if identities.len() < 3
        || identities.len() > 64
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.contains(['\0', '\r', '\n', ' '])
        })
    {
        return Err("PLATFORM_SRE_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

fn sha256(value: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value))
}
