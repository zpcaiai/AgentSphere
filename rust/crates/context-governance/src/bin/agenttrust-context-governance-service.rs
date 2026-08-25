use agent_trust_context_governance::adapters::{
    AdapterEndpoint, ContextAdapterEndpoints, ContextEvidenceKeyring, HttpContextOrchestrator,
    HttpContextRuntime,
};
use agent_trust_context_governance::authority::{
    ContextAuthorityConfig, ContextExecutor, ContextIngressAuthority,
    PostgresContextAuthorityStore, RetrievalAuthorizer,
};
use agent_trust_context_governance::server::{
    ContextServerConfig, ContextTokenAuthorizer, router, serve,
};
use agent_trust_contracts::{AgentInstanceId, ToolId, ToolVersion};
use nix::unistd::{Gid, Uid};
use reqwest::{Certificate, Identity};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("CONTEXT_GOVERNANCE_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("AGENT_TRUST_PROFILE")? != "production" || Uid::effective().is_root() {
        return Err("CONTEXT_PRODUCTION_PROFILE_REQUIRED".into());
    }
    let database_url = read_secret_file("AGENT_TRUST_CONTEXT_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password =
        read_secret_file("AGENT_TRUST_CONTEXT_DATABASE_PASSWORD_FILE", 16, 8192)?;
    let expected_role = required_identifier("AGENT_TRUST_CONTEXT_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_path("AGENT_TRUST_CONTEXT_DATABASE_CA_FILE")?;
    let options = database_options(
        &database_url,
        &database_password,
        &database_ca,
        &expected_role,
    )?;
    database_password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(
            required_i64("AGENT_TRUST_CONTEXT_DATABASE_MAX_CONNECTIONS", 4, 50)? as u32,
        )
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_secs(60))
        .max_lifetime(std::time::Duration::from_secs(900))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_CONTEXT_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_CONTEXT_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_CONTEXT_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let store = PostgresContextAuthorityStore::new(pool);
    let orchestrator = Arc::new(HttpContextOrchestrator::new(
        outbound.clone(),
        adapter_endpoint(
            "AGENT_TRUST_CONTEXT_ORCHESTRATOR_ENDPOINT",
            "AGENT_TRUST_CONTEXT_ORCHESTRATOR_TOKEN_FILE",
        )?,
    )?);
    let service_subject = required_identifier("AGENT_TRUST_CONTEXT_SERVICE_SUBJECT")?;
    let ingress = ContextIngressAuthority::new(
        store.clone(),
        orchestrator,
        ContextAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_CONTEXT_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_CONTEXT_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_CONTEXT_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_CONTEXT_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_CONTEXT_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_CONTEXT_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_CONTEXT_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject,
        },
    )?;
    let runtime = Arc::new(HttpContextRuntime::new(
        outbound,
        ContextAdapterEndpoints {
            object_store: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_OBJECT_STORE_ENDPOINT",
                "AGENT_TRUST_CONTEXT_OBJECT_STORE_TOKEN_FILE",
            )?,
            vector_index: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_VECTOR_INDEX_ENDPOINT",
                "AGENT_TRUST_CONTEXT_VECTOR_INDEX_TOKEN_FILE",
            )?,
            cache: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_CACHE_ENDPOINT",
                "AGENT_TRUST_CONTEXT_CACHE_TOKEN_FILE",
            )?,
            supply_chain: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_SUPPLY_CHAIN_ENDPOINT",
                "AGENT_TRUST_CONTEXT_SUPPLY_CHAIN_TOKEN_FILE",
            )?,
            legal_hold: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_LEGAL_HOLD_ENDPOINT",
                "AGENT_TRUST_CONTEXT_LEGAL_HOLD_TOKEN_FILE",
            )?,
            poisoning: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_POISONING_ENDPOINT",
                "AGENT_TRUST_CONTEXT_POISONING_TOKEN_FILE",
            )?,
            evidence: adapter_endpoint(
                "AGENT_TRUST_CONTEXT_EVIDENCE_ENDPOINT",
                "AGENT_TRUST_CONTEXT_EVIDENCE_TOKEN_FILE",
            )?,
        },
        required_identifier("AGENT_TRUST_CONTEXT_EVIDENCE_CLIENT_IDENTITY")?,
        ContextEvidenceKeyring::from_json(&std::fs::read(required_path(
            "AGENT_TRUST_CONTEXT_EVIDENCE_KEYRING_FILE",
        )?)?)?,
    )?);
    let executor = ContextExecutor::new(
        store.clone(),
        runtime.clone(),
        required_i64("AGENT_TRUST_CONTEXT_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;
    let retrieval = RetrievalAuthorizer::new(store, runtime);
    let allowed_identities = required_identities("AGENT_TRUST_CONTEXT_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(ContextTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_CONTEXT_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let application = router(ingress.clone(), executor.clone(), retrieval, tokens.clone());
    let listen: IpAddr = env::var("AGENT_TRUST_CONTEXT_LISTEN_ADDRESS")?.parse()?;
    let management_listen: IpAddr =
        env::var("AGENT_TRUST_CONTEXT_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    serve(
        ContextServerConfig {
            data_address: SocketAddr::new(
                listen,
                required_i64("AGENT_TRUST_CONTEXT_PORT", 8_095, 8_095)? as u16,
            ),
            management_address: SocketAddr::new(
                management_listen,
                required_i64("AGENT_TRUST_CONTEXT_MANAGEMENT_PORT", 9_105, 9_105)? as u16,
            ),
            tls_ca_file: required_path("AGENT_TRUST_CONTEXT_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_CONTEXT_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_CONTEXT_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: allowed_identities,
            recovery_interval_seconds: required_i64(
                "AGENT_TRUST_CONTEXT_RECOVERY_INTERVAL_SECONDS",
                5,
                300,
            )? as u64,
        },
        application,
        tokens,
        ingress,
        executor,
    )
    .await?;
    Ok(())
}

fn adapter_endpoint(
    endpoint_name: &str,
    token_name: &str,
) -> Result<AdapterEndpoint, Box<dyn std::error::Error>> {
    Ok(AdapterEndpoint {
        endpoint: required_url(endpoint_name)?,
        token_file: required_private_path(token_name)?,
    })
}

async fn verify_database_role(
    pool: &sqlx::PgPool,
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
                rolreplication,rolinherit,rolcanlogin,current_setting('search_path') AS search_path,\
                current_schemas(true)::text AS schemas,current_setting('row_security') AS row_security,\
                has_schema_privilege(current_user,'public','CREATE') AS can_create,\
                has_database_privilege(current_user,current_database(),'TEMP') AS can_temp,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND table_name<>ALL(ARRAY[\
                    'governed_memory_entries','prompt_versions','knowledge_snapshots',\
                    'context_knowledge_sources','context_deletion_tombstones',\
                    'context_quarantine_records','context_resource_versions','context_action_ingress',\
                    'context_authority_executions','context_retrieval_decisions',\
                    'context_evidence_outbox'])) AS cross_domain_table_grant,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type IN \
                    ('UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER')) AS broad_mutation_grant,\
                EXISTS (SELECT 1 FROM information_schema.role_routine_grants WHERE grantee=current_user \
                  AND routine_schema='public' AND privilege_type='EXECUTE') AS can_execute_function,\
                (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type IN ('SELECT','INSERT') \
                  AND table_name=ANY(ARRAY[\
                    'governed_memory_entries','prompt_versions','knowledge_snapshots',\
                    'context_knowledge_sources','context_deletion_tombstones',\
                    'context_quarantine_records','context_resource_versions','context_action_ingress',\
                    'context_authority_executions','context_retrieval_decisions',\
                    'context_evidence_outbox'])) AS base_grant_count,\
                EXISTS (SELECT 1 FROM information_schema.role_column_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type='UPDATE' AND NOT (\
                    (table_name='governed_memory_entries' AND column_name=ANY(ARRAY[\
                      'status','ledger_execution_id','fence_digest','resource_version',\
                      'quarantine_reason_digest','updated_at'])) OR\
                    (table_name='prompt_versions' AND column_name=ANY(ARRAY[\
                      'status','rollout_percent','resource_version','activated_at','updated_at'])) OR\
                    (table_name='knowledge_snapshots' AND column_name=ANY(ARRAY[\
                      'quarantined','resource_version','updated_at','index_ref','tombstoned'])) OR\
                    (table_name='context_knowledge_sources' AND column_name=ANY(ARRAY[\
                      'quarantined','resource_version','updated_at'])) OR\
                    (table_name='context_quarantine_records' AND column_name=ANY(ARRAY[\
                      'released_by','remediation_evidence_ref','remediation_evidence_digest','released_at'])) OR\
                    (table_name='context_resource_versions' AND column_name=ANY(ARRAY[\
                      'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'])) OR\
                    (table_name='context_action_ingress' AND column_name=ANY(ARRAY[\
                      'state','receipt','updated_at'])) OR\
                    (table_name='context_authority_executions' AND column_name=ANY(ARRAY[\
                      'state','external_receipts','safe_result','evidence_request','evidence_ref',\
                      'evidence_digest','evidence_receipt','stable_error','execution_owner',\
                      'execution_lease_until','updated_at'])) OR\
                    (table_name='context_evidence_outbox' AND column_name='delivered_at')\
                  )) AS unexpected_update_column,\
                (SELECT count(*) FROM information_schema.role_column_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type='UPDATE') AS update_column_count \
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
        || !row.try_get::<bool, _>("rolcanlogin")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_temp")?
        || row.try_get::<bool, _>("cross_domain_table_grant")?
        || row.try_get::<bool, _>("broad_mutation_grant")?
        || row.try_get::<bool, _>("can_execute_function")?
        || row.try_get::<i64, _>("base_grant_count")? != 22
        || row.try_get::<bool, _>("unexpected_update_column")?
        || row.try_get::<i64, _>("update_column_count")? != 43
    {
        return Err("CONTEXT_DATABASE_ROLE_UNSAFE".into());
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
            return Err("CONTEXT_DATABASE_URL_INVALID".into());
        }
    }
    let database = parsed.path().strip_prefix('/').unwrap_or("");
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username() != expected_role
        || parsed.password().is_some()
        || database.is_empty()
        || database.contains('/')
        || parsed.fragment().is_some()
        || query.keys().any(|key| {
            !matches!(
                key.as_str(),
                "sslmode" | "connect_timeout" | "application_name"
            )
        })
        || query.get("sslmode").map(String::as_str) != Some("verify-full")
        || query.get("application_name").map(String::as_str)
            != Some("agenttrust-context-governance")
    {
        return Err("CONTEXT_DATABASE_URL_INVALID".into());
    }
    let port = parsed.port().unwrap_or(5432);
    Ok(PgConnectOptions::new()
        .host(parsed.host_str().ok_or("CONTEXT_DATABASE_HOST_MISSING")?)
        .port(port)
        .username(expected_role)
        .password(password)
        .database(database)
        .application_name("agenttrust-context-governance")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file)
        .statement_cache_capacity(128))
}

fn outbound_client(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let ca = std::fs::read(ca_file)?;
    let certificate = Certificate::from_pem(&ca)?;
    let mut identity_pem = std::fs::read(certificate_file)?;
    let mut key = std::fs::read(private_key_file)?;
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key);
    let identity = Identity::from_pem(&identity_pem)?;
    key.zeroize();
    identity_pem.zeroize();
    Ok(reqwest::Client::builder()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .identity(identity)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(20))
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(8)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("agenttrust-context-governance/1")
        .build()?)
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
        return Err("CONTEXT_SECRET_FILE_INVALID".into());
    }
    Ok(trimmed.into())
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > 16 * 1024 * 1024
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = required_path(name)?;
    let metadata = std::fs::metadata(&path)?;
    let mode = metadata.mode() & 0o777;
    let effective_uid = Uid::effective().as_raw();
    let effective_gid = Gid::effective().as_raw();
    let allowed = 0o400
        | if metadata.gid() == effective_gid {
            0o040
        } else {
            0
        };
    let readable = (metadata.uid() == effective_uid && mode & 0o400 != 0)
        || (metadata.gid() == effective_gid && mode & 0o040 != 0);
    if !readable || mode & !allowed != 0 {
        return Err(format!("{name}_PERMISSIONS_UNSAFE").into());
    }
    Ok(path)
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
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let parsed = uuid::Uuid::parse_str(&raw)?;
    if parsed.to_string() != raw {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(raw)
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
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let value = raw.parse::<i64>()?;
    if value < minimum || value > maximum || value.to_string() != raw {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let values = env::var(name)?
        .split(',')
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if values.is_empty()
        || values.len() > 128
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 512
                || !(value.starts_with("DNS:") || value.starts_with("URI:"))
                || !value.bytes().all(|byte| byte.is_ascii_graphic())
        })
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(values)
}
