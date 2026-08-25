use agent_trust_model_gateway::adapters::{
    AdapterEndpoint, HttpProductionModelRuntime, ModelRuntimeEndpoints,
};
use agent_trust_model_gateway::authority::{ModelExecutionAuthority, PostgresModelAuthorityStore};
use agent_trust_model_gateway::server::{
    ModelServerConfig, ModelTokenAuthorizer, router, serve, validate_private_file,
};
use nix::unistd::Uid;
use reqwest::{Certificate, Identity};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Row};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("MODEL_GATEWAY_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("AGENT_TRUST_PROFILE")? != "production" || Uid::effective().is_root() {
        return Err("MODEL_GATEWAY_PRODUCTION_PROFILE_REQUIRED".into());
    }
    let database_url = read_secret_file("AGENT_TRUST_MODEL_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password =
        read_secret_file("AGENT_TRUST_MODEL_DATABASE_PASSWORD_FILE", 16, 8192)?;
    let expected_role = required_identifier("AGENT_TRUST_MODEL_DATABASE_EXPECTED_ROLE")?;
    let options = database_options(
        &database_url,
        &database_password,
        &required_path("AGENT_TRUST_MODEL_DATABASE_CA_FILE")?,
        &expected_role,
    )?;
    database_password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(required_i64("AGENT_TRUST_MODEL_DATABASE_MAX_CONNECTIONS", 4, 50)? as u32)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_secs(60))
        .max_lifetime(std::time::Duration::from_secs(900))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_MODEL_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_MODEL_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_MODEL_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let runtime = Arc::new(HttpProductionModelRuntime::from_files(
        pool.clone(),
        outbound,
        ModelRuntimeEndpoints {
            data_policy: adapter_endpoint(
                "AGENT_TRUST_MODEL_DATA_POLICY_ENDPOINT",
                "AGENT_TRUST_MODEL_DATA_POLICY_TOKEN_FILE",
            )?,
            dlp: adapter_endpoint(
                "AGENT_TRUST_MODEL_DLP_ENDPOINT",
                "AGENT_TRUST_MODEL_DLP_TOKEN_FILE",
            )?,
            sanitizer: adapter_endpoint(
                "AGENT_TRUST_MODEL_DATA_SANITIZER_ENDPOINT",
                "AGENT_TRUST_MODEL_DATA_SANITIZER_TOKEN_FILE",
            )?,
            artifact_authorizer: adapter_endpoint(
                "AGENT_TRUST_MODEL_DATA_ARTIFACT_AUTHORIZER_ENDPOINT",
                "AGENT_TRUST_MODEL_DATA_ARTIFACT_AUTHORIZER_TOKEN_FILE",
            )?,
            data_mutation: adapter_endpoint(
                "AGENT_TRUST_MODEL_DATA_MUTATION_ENDPOINT",
                "AGENT_TRUST_MODEL_DATA_MUTATION_TOKEN_FILE",
            )?,
            data_read: adapter_endpoint(
                "AGENT_TRUST_MODEL_DATA_READ_ENDPOINT",
                "AGENT_TRUST_MODEL_DATA_READ_TOKEN_FILE",
            )?,
            artifact_store: adapter_endpoint(
                "AGENT_TRUST_MODEL_ARTIFACT_STORE_ENDPOINT",
                "AGENT_TRUST_MODEL_ARTIFACT_STORE_TOKEN_FILE",
            )?,
            artifact_store_jurisdiction: required_identifier(
                "AGENT_TRUST_MODEL_ARTIFACT_STORE_JURISDICTION",
            )?,
            artifact_store_destination_kind: required_identifier(
                "AGENT_TRUST_MODEL_ARTIFACT_STORE_DESTINATION_KIND",
            )?,
            evidence: adapter_endpoint(
                "AGENT_TRUST_MODEL_EVIDENCE_ENDPOINT",
                "AGENT_TRUST_MODEL_EVIDENCE_TOKEN_FILE",
            )?,
            evidence_source_service: required_single_identity(
                "AGENT_TRUST_MODEL_EVIDENCE_SOURCE_SERVICE",
            )?,
        },
        &required_private_path("AGENT_TRUST_MODEL_PROVIDER_ENDPOINTS_FILE")?,
        &required_private_path("AGENT_TRUST_MODEL_PROVIDER_KEYRING_FILE")?,
        &required_private_path("AGENT_TRUST_MODEL_EVIDENCE_KEYRING_FILE")?,
    )?);
    let store = PostgresModelAuthorityStore::new(pool);
    let authority = ModelExecutionAuthority::new(
        store,
        runtime,
        required_uuid("AGENT_TRUST_MODEL_INSTANCE_ID")?,
        required_i64("AGENT_TRUST_MODEL_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;
    let identities = required_identities("AGENT_TRUST_MODEL_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(ModelTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_MODEL_TOKEN_BINDINGS_FILE")?,
        &identities,
    )?);
    let application = router(authority.clone(), tokens.clone());
    let listen: IpAddr = env::var("AGENT_TRUST_MODEL_LISTEN_ADDRESS")?.parse()?;
    let management_listen: IpAddr =
        env::var("AGENT_TRUST_MODEL_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    serve(
        ModelServerConfig {
            data_address: SocketAddr::new(listen, exact_port("AGENT_TRUST_MODEL_PORT", 8091)?),
            management_address: SocketAddr::new(
                management_listen,
                exact_port("AGENT_TRUST_MODEL_MANAGEMENT_PORT", 9101)?,
            ),
            tls_ca_file: required_path("AGENT_TRUST_MODEL_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_MODEL_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path("AGENT_TRUST_MODEL_TLS_PRIVATE_KEY_FILE")?,
            allowed_client_identities: identities,
            recovery_interval_seconds: required_i64(
                "AGENT_TRUST_MODEL_RECOVERY_INTERVAL_SECONDS",
                5,
                300,
            )? as u64,
        },
        application,
        tokens,
        authority,
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

fn outbound_client(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    validate_regular_file(ca_file, 4 * 1_048_576, false)?;
    validate_regular_file(certificate_file, 4 * 1_048_576, false)?;
    validate_private_file(private_key_file, 4 * 1_048_576)?;
    let ca = Certificate::from_pem(&std::fs::read(ca_file)?)?;
    let mut identity_pem = Zeroizing::new(std::fs::read(certificate_file)?);
    identity_pem.extend_from_slice(&std::fs::read(private_key_file)?);
    let identity = Identity::from_pem(identity_pem.as_slice())?;
    Ok(reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(300))
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(8)
        .build()?)
}

fn database_options(
    database_url: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    validate_regular_file(ca_file, 4 * 1_048_576, false)?;
    let parsed = Url::parse(database_url)?;
    let mut query = std::collections::BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized = key.to_ascii_lowercase();
        if key.as_ref() != normalized
            || value.is_empty()
            || query.insert(normalized, value.into_owned()).is_some()
        {
            return Err("MODEL_DATABASE_URL_INVALID".into());
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
        || query.get("application_name").map(String::as_str) != Some("agenttrust-model-gateway")
    {
        return Err("MODEL_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::new()
        .host(parsed.host_str().ok_or("MODEL_DATABASE_HOST_MISSING")?)
        .port(parsed.port().unwrap_or(5432))
        .username(expected_role)
        .password(password)
        .database(database)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert(ca_file)
        .application_name("agenttrust-model-gateway")
        .statement_cache_capacity(128))
}

async fn verify_database_role(
    pool: &PgPool,
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
         rolreplication,rolinherit,rolcanlogin,current_setting('row_security') AS row_security,\
         has_schema_privilege(current_user,'public','CREATE') AS can_create,\
         has_database_privilege(current_user,current_database(),'TEMP') AS can_temp,\
         EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
           AND table_schema='public' AND table_name<>ALL(ARRAY[\
             'model_provider_revisions','model_provider_revocations',\
             'model_tenant_provider_approvals','model_budget_accounts',\
             'model_gateway_requests','model_budget_reservations','model_stream_chunk_digests',\
             'model_execution_evidence','model_billing_usage_lines',\
             'model_billing_reconciliations','model_evidence_outbox',\
             'model_authority_evidence_outbox','model_data_governance_outbox'])) \
           AS cross_domain_grant,\
         EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
           AND table_schema='public' AND privilege_type IN ('DELETE','TRUNCATE','REFERENCES','TRIGGER')) \
           AS destructive_grant,\
         EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
           AND table_schema='public' AND privilege_type='UPDATE') AS table_update_grant,\
         EXISTS (SELECT 1 FROM information_schema.role_column_grants WHERE grantee=current_user \
           AND table_schema='public' AND privilege_type='UPDATE' AND NOT (\
             (table_name='model_budget_accounts' AND column_name=ANY(ARRAY[\
               'reserved_microunits','spent_microunits','account_version','updated_at'])) OR\
             (table_name='model_gateway_requests' AND column_name=ANY(ARRAY[\
               'state','owner_instance_id','lease_expires_at','selected_provider_key',\
               'provider_request_id','output_digest','output_artifact_ref','output_artifact_digest',\
               'safe_response','stable_error','evidence_ref','evidence_digest','updated_at','completed_at'])) OR\
             (table_name='model_budget_reservations' AND column_name=ANY(ARRAY[\
               'actual_microunits','state','provider_key','provider_request_id','finalized_at'])) OR\
             (table_name='model_billing_usage_lines' AND column_name=ANY(ARRAY[\
               'provider_statement_digest','reconciliation_state','reconciled_at'])) OR\
             (table_name='model_authority_evidence_outbox' AND column_name=ANY(ARRAY[\
               'state','signed_receipt','evidence_ref','evidence_digest','updated_at','delivered_at'])) OR\
             (table_name='model_data_governance_outbox' AND column_name=ANY(ARRAY[\
               'state','mutation_result','evidence_ref','evidence_digest','updated_at','completed_at']))\
           )) AS unexpected_column_update,\
         EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
           AND table_schema='public' AND privilege_type='INSERT' AND table_name<>ALL(ARRAY[\
             'model_gateway_requests','model_budget_reservations','model_stream_chunk_digests',\
             'model_execution_evidence','model_billing_usage_lines',\
             'model_billing_reconciliations','model_evidence_outbox',\
             'model_authority_evidence_outbox','model_data_governance_outbox'])) AS unexpected_insert,\
         EXISTS (SELECT 1 FROM information_schema.role_routine_grants WHERE grantee=current_user \
           AND routine_schema='public' AND privilege_type='EXECUTE') AS function_grant",
    )
    .fetch_one(pool)
    .await?;
    let valid = row.try_get::<String, _>("role_name")? == expected_role
        && !row.try_get::<bool, _>("rolsuper")?
        && !row.try_get::<bool, _>("rolbypassrls")?
        && !row.try_get::<bool, _>("rolcreatedb")?
        && !row.try_get::<bool, _>("rolcreaterole")?
        && !row.try_get::<bool, _>("rolreplication")?
        && !row.try_get::<bool, _>("rolinherit")?
        && row.try_get::<bool, _>("rolcanlogin")?
        && row.try_get::<String, _>("row_security")? == "on"
        && !row.try_get::<bool, _>("can_create")?
        && !row.try_get::<bool, _>("can_temp")?
        && !row.try_get::<bool, _>("cross_domain_grant")?
        && !row.try_get::<bool, _>("destructive_grant")?
        && !row.try_get::<bool, _>("table_update_grant")?
        && !row.try_get::<bool, _>("unexpected_column_update")?
        && !row.try_get::<bool, _>("unexpected_insert")?
        && !row.try_get::<bool, _>("function_grant")?;
    if !valid {
        return Err("MODEL_DATABASE_ROLE_NOT_LEAST_PRIVILEGE".into());
    }
    Ok(())
}

fn exact_port(name: &str, expected: u16) -> Result<u16, Box<dyn std::error::Error>> {
    let value = env::var(name)?.parse::<u16>()?;
    if value != expected {
        return Err("MODEL_GATEWAY_PORT_CONTRACT_INVALID".into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value = env::var(name)?.parse::<i64>()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("MODEL_GATEWAY_INTEGER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<Uuid, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let value = Uuid::parse_str(&raw)?;
    if value.to_string() != raw || value.is_nil() {
        return Err("MODEL_GATEWAY_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err("MODEL_GATEWAY_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let identities = raw.split(',').map(str::to_owned).collect::<BTreeSet<_>>();
    if identities.is_empty()
        || identities.len() > 1000
        || identities.iter().any(|identity| {
            identity.is_empty()
                || identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.bytes().any(|byte| byte.is_ascii_whitespace())
        })
    {
        return Err("MODEL_GATEWAY_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

fn required_single_identity(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let identities = required_identities(name)?;
    if identities.len() != 1 {
        return Err("MODEL_GATEWAY_IDENTITY_INVALID".into());
    }
    identities
        .into_iter()
        .next()
        .ok_or_else(|| "MODEL_GATEWAY_IDENTITY_INVALID".into())
}

fn required_url(name: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let value = Url::parse(&env::var(name)?)?;
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != "/"
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err("MODEL_GATEWAY_ENDPOINT_INVALID".into());
    }
    Ok(value)
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    validate_regular_file(&path, 4 * 1_048_576, false)?;
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    validate_private_file(&path, 4 * 1_048_576)?;
    Ok(path)
}

fn read_secret_file(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let path = required_private_path(name)?;
    let value = Zeroizing::new(std::fs::read_to_string(path)?);
    if value.trim() != value.as_str()
        || !(minimum..=maximum).contains(&value.len())
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("MODEL_GATEWAY_SECRET_INVALID".into());
    }
    Ok(value)
}

fn validate_regular_file(
    path: &Path,
    maximum: u64,
    private: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != Uid::effective().as_raw()
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
    {
        return Err("MODEL_GATEWAY_FILE_POSTURE_INVALID".into());
    }
    Ok(())
}
