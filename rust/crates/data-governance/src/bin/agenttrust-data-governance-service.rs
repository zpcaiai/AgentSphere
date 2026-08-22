use agent_trust_contracts::{AgentInstanceId, PolicyVersion, ToolId, ToolVersion};
use agent_trust_data_governance::DeploymentPolicy;
use agent_trust_data_governance::adapters::{
    AdapterEndpoint, DataAdapterEndpoints, EvidenceReceiptVerification, HttpDataOrchestrator,
    HttpDataRuntime,
};
use agent_trust_data_governance::authority::{
    DataAuthorityConfig, DataExecutor, DataIngressAuthority, PostgresDataAuthorityStore,
};
use agent_trust_data_governance::server::{
    DataServerConfig, DataTokenAuthorizer, router, serve, strict_json,
};
use agent_trust_data_governance::service::DataDecisionService;
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nix::unistd::{Gid, Uid};
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("DATA_GOVERNANCE_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("AGENT_TRUST_PROFILE")? != "production" || Uid::effective().is_root() {
        return Err("DATA_GOVERNANCE_PRODUCTION_PROFILE_REQUIRED".into());
    }
    let database_url = read_secret_file("AGENT_TRUST_DATA_DATABASE_URL_FILE", 16, 16_384)?;
    let mut database_password =
        read_secret_file("AGENT_TRUST_DATA_DATABASE_PASSWORD_FILE", 16, 8192)?;
    let expected_role = required_identifier("AGENT_TRUST_DATA_DATABASE_EXPECTED_ROLE")?;
    let database_ca = required_path("AGENT_TRUST_DATA_DATABASE_CA_FILE")?;
    let options = database_options(
        &database_url, &database_password, &database_ca, &expected_role,
    )?;
    database_password.zeroize();
    let pool = PgPoolOptions::new()
        .min_connections(2)
        .max_connections(required_i64("AGENT_TRUST_DATA_DATABASE_MAX_CONNECTIONS", 4, 50)? as u32)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_secs(60))
        .max_lifetime(std::time::Duration::from_secs(900))
        .connect_with(options)
        .await?;
    verify_database_role(&pool, &expected_role).await?;

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_DATA_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_DATA_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_DATA_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let store = PostgresDataAuthorityStore::new(pool);
    let orchestrator = Arc::new(HttpDataOrchestrator::new(
        outbound.clone(),
        adapter_endpoint(
            "AGENT_TRUST_DATA_ORCHESTRATOR_ENDPOINT",
            "AGENT_TRUST_DATA_ORCHESTRATOR_TOKEN_FILE",
            "AGENT_TRUST_DATA_ORCHESTRATOR_READINESS_SCHEMA",
        )?,
    )?);
    let evidence_verification = EvidenceReceiptVerification::new(
        required_mtls_identity("AGENT_TRUST_DATA_EVIDENCE_SOURCE_SERVICE")?,
        required_identifier("AGENT_TRUST_DATA_EVIDENCE_ISSUER")?,
        load_evidence_keyring(&required_path(
            "AGENT_TRUST_DATA_EVIDENCE_VERIFYING_KEYRING_FILE",
        )?)?,
    )?;
    let runtime = Arc::new(HttpDataRuntime::new(
        outbound,
        DataAdapterEndpoints {
            enterprise_dlp: adapter_endpoint(
                "AGENT_TRUST_DATA_ENTERPRISE_DLP_ENDPOINT",
                "AGENT_TRUST_DATA_ENTERPRISE_DLP_TOKEN_FILE",
                "AGENT_TRUST_DATA_ENTERPRISE_DLP_READINESS_SCHEMA",
            )?,
            object_worm: adapter_endpoint(
                "AGENT_TRUST_DATA_OBJECT_WORM_ENDPOINT",
                "AGENT_TRUST_DATA_OBJECT_WORM_TOKEN_FILE",
                "AGENT_TRUST_DATA_OBJECT_WORM_READINESS_SCHEMA",
            )?,
            legal_hold: adapter_endpoint(
                "AGENT_TRUST_DATA_LEGAL_HOLD_ENDPOINT",
                "AGENT_TRUST_DATA_LEGAL_HOLD_TOKEN_FILE",
                "AGENT_TRUST_DATA_LEGAL_HOLD_READINESS_SCHEMA",
            )?,
            evidence: adapter_endpoint(
                "AGENT_TRUST_DATA_EVIDENCE_ENDPOINT",
                "AGENT_TRUST_DATA_EVIDENCE_TOKEN_FILE",
                "AGENT_TRUST_DATA_EVIDENCE_READINESS_SCHEMA",
            )?,
        },
        evidence_verification,
    )?);
    let service_subject = required_identifier("AGENT_TRUST_DATA_SERVICE_SUBJECT")?;
    let ingress = DataIngressAuthority::new(
        store.clone(),
        orchestrator,
        DataAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_DATA_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_DATA_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_DATA_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_DATA_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_DATA_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_DATA_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_DATA_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject,
        },
    )?;
    let executor = DataExecutor::new(
        store.clone(),
        runtime.clone(),
        required_i64("AGENT_TRUST_DATA_EXECUTION_LEASE_SECONDS", 15, 300)?,
    )?;
    let signed_profiles = load_signed_profiles(
        &required_path("AGENT_TRUST_DATA_DEPLOYMENT_PROFILES_FILE")?,
        &required_path("AGENT_TRUST_DATA_PROFILE_KEYRING_FILE")?,
    )?;
    let decision = DataDecisionService::new(
        PolicyVersion(signed_profiles.policy_version),
        signed_profiles.profiles,
        runtime,
        store,
    )?;
    let allowed_identities = required_identities("AGENT_TRUST_DATA_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(DataTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_DATA_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let application = router(
        ingress.clone(), executor.clone(), decision.clone(), tokens.clone(),
    );
    let listen: IpAddr = env::var("AGENT_TRUST_DATA_LISTEN_ADDRESS")?.parse()?;
    let management_listen: IpAddr =
        env::var("AGENT_TRUST_DATA_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    required_exact_port("AGENT_TRUST_DATA_PORT", 8092)?;
    required_exact_port("AGENT_TRUST_DATA_MANAGEMENT_PORT", 9102)?;
    serve(
        DataServerConfig {
            data_address: SocketAddr::new(listen, 8092),
            management_address: SocketAddr::new(management_listen, 9102),
            tls_ca_file: required_path("AGENT_TRUST_DATA_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_DATA_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_DATA_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: allowed_identities,
            recovery_interval_seconds: u64::try_from(required_i64(
                "AGENT_TRUST_DATA_RECOVERY_INTERVAL_SECONDS", 5, 300,
            )?)?,
        },
        application,
        tokens,
        ingress,
        executor,
        decision,
    ).await?;
    Ok(())
}

fn adapter_endpoint(
    endpoint_name: &str,
    token_name: &str,
    readiness_schema_name: &str,
) -> Result<AdapterEndpoint, Box<dyn std::error::Error>> {
    Ok(AdapterEndpoint {
        endpoint: required_url(endpoint_name)?,
        token_file: required_private_path(token_name)?,
        readiness_schema: required_identifier(readiness_schema_name)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedDeploymentProfiles {
    schema_version: String,
    policy_version: String,
    key_id: String,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    profiles: Vec<DeploymentPolicy>,
    signature_algorithm: String,
    signature: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileSigningMaterial<'a> {
    schema_version: &'a str,
    policy_version: &'a str,
    key_id: &'a str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    profiles: &'a [DeploymentPolicy],
    signature_algorithm: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileKeyring {
    schema_version: String,
    keys: BTreeMap<String, String>,
    revoked_key_ids: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidencePublicKeyring {
    schema_version: String,
    keys: BTreeMap<String, String>,
}

fn load_evidence_keyring(
    path: &Path,
) -> Result<BTreeMap<String, VerifyingKey>, Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)?;
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err("DATA_EVIDENCE_KEYRING_INVALID".into());
    }
    let keyring: EvidencePublicKeyring = strict_json(&raw)?;
    if keyring.schema_version != "agenttrust.ed25519-public-keyring.v1"
        || keyring.keys.is_empty()
        || keyring.keys.len() > 1_024
    {
        return Err("DATA_EVIDENCE_KEYRING_INVALID".into());
    }
    let mut keys = BTreeMap::new();
    for (key_id, encoded) in keyring.keys {
        if !config_identifier(&key_id, 128) || encoded.len() != 43 {
            return Err("DATA_EVIDENCE_KEYRING_INVALID".into());
        }
        let bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| "DATA_EVIDENCE_KEYRING_INVALID")?
            .try_into()
            .map_err(|_| "DATA_EVIDENCE_KEYRING_INVALID")?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| "DATA_EVIDENCE_KEYRING_INVALID")?;
        if keys.insert(key_id, key).is_some() {
            return Err("DATA_EVIDENCE_KEYRING_INVALID".into());
        }
    }
    Ok(keys)
}

fn load_signed_profiles(
    profile_path: &Path,
    keyring_path: &Path,
) -> Result<SignedDeploymentProfiles, Box<dyn std::error::Error>> {
    let raw = std::fs::read(profile_path)?;
    let keyring_raw = std::fs::read(keyring_path)?;
    if raw.is_empty() || raw.len() > 1_048_576
        || keyring_raw.is_empty() || keyring_raw.len() > 1_048_576
    {
        return Err("DATA_PROFILE_DOCUMENT_INVALID".into());
    }
    let document: SignedDeploymentProfiles = strict_json(&raw)?;
    let keyring: ProfileKeyring = strict_json(&keyring_raw)?;
    let now = Utc::now();
    if document.schema_version != "agenttrust.signed-deployment-profiles.v1"
        || document.signature_algorithm != "Ed25519"
        || !config_identifier(&document.policy_version, 256)
        || !config_identifier(&document.key_id, 256)
        || document.profiles.is_empty()
        || document.profiles.len() > 100
        || document.issued_at > now
        || document.expires_at <= now
        || document.expires_at > document.issued_at + chrono::Duration::days(90)
        || keyring.schema_version != "agenttrust.data-profile-keyring.v1"
        || keyring.keys.is_empty()
        || keyring.keys.len() > 100
        || keyring.revoked_key_ids.len() > 100
        || keyring.keys.iter().any(|(key_id, encoded)| {
            !config_identifier(key_id, 256)
                || STANDARD
                    .decode(encoded)
                    .map_or(true, |value| value.len() != 32)
        })
        || keyring
            .revoked_key_ids
            .iter()
            .any(|key_id| !config_identifier(key_id, 256))
        || keyring.revoked_key_ids.contains(&document.key_id)
    {
        return Err("DATA_PROFILE_DOCUMENT_INVALID".into());
    }
    let public_key = keyring.keys.get(&document.key_id)
        .ok_or("DATA_PROFILE_KEY_UNKNOWN")?;
    let public_key: [u8; 32] = STANDARD.decode(public_key)?
        .try_into().map_err(|_| "DATA_PROFILE_KEY_INVALID")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)?;
    let signature = Signature::from_slice(&STANDARD.decode(&document.signature)?)?;
    let material = ProfileSigningMaterial {
        schema_version: &document.schema_version,
        policy_version: &document.policy_version,
        key_id: &document.key_id,
        issued_at: document.issued_at,
        expires_at: document.expires_at,
        profiles: &document.profiles,
        signature_algorithm: &document.signature_algorithm,
    };
    let bytes = serde_jcs::to_vec(&material)?;
    verifying_key.verify(&bytes, &signature)?;
    let mut profile_ids = BTreeSet::new();
    if document.profiles.iter().any(|profile| {
        profile.validate().is_err() || !profile_ids.insert(profile.profile_id.clone())
    }) {
        return Err("DATA_PROFILE_DOCUMENT_INVALID".into());
    }
    Ok(document)
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
                    'data_resource_versions','data_authority_ingress','data_authority_executions',\
                    'governed_data_labels','data_policy_decision_records','data_dlp_scan_summaries',\
                    'data_transform_receipts','data_cross_domain_grants',\
                    'data_cross_domain_consumptions','data_retention_records','data_legal_holds',\
                    'data_export_intents','data_evidence_outbox'])) AS cross_domain_table_grant,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type IN \
                    ('UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER')) AS broad_mutation_grant,\
                EXISTS (SELECT 1 FROM information_schema.role_routine_grants WHERE grantee=current_user \
                  AND routine_schema='public' AND privilege_type='EXECUTE') AS can_execute_function,\
                (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type IN ('SELECT','INSERT') \
                  AND table_name=ANY(ARRAY[\
                    'data_resource_versions','data_authority_ingress','data_authority_executions',\
                    'governed_data_labels','data_policy_decision_records','data_dlp_scan_summaries',\
                    'data_transform_receipts','data_cross_domain_grants',\
                    'data_cross_domain_consumptions','data_retention_records','data_legal_holds',\
                    'data_export_intents','data_evidence_outbox'])) AS base_grant_count,\
                EXISTS (SELECT 1 FROM information_schema.role_column_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type='UPDATE' AND NOT (\
                    (table_name='data_resource_versions' AND column_name=ANY(ARRAY[\
                      'resource_version','action_hash','ledger_execution_id','fence_digest','updated_at'])) OR\
                    (table_name='data_authority_ingress' AND column_name=ANY(ARRAY[\
                      'state','receipt','updated_at'])) OR\
                    (table_name='data_authority_executions' AND column_name=ANY(ARRAY[\
                      'state','execution_owner','execution_lease_until','evidence_event_id','result',\
                      'completed_at','updated_at'])) OR\
                    (table_name='data_cross_domain_grants' AND column_name=ANY(ARRAY[\
                      'consumed_at','consumption_id'])) OR\
                    (table_name='data_legal_holds' AND column_name=ANY(ARRAY[\
                      'state','released_at','release_approval_id','release_evidence_ref',\
                      'release_evidence_digest','release_adapter_receipt','release_action_hash',\
                      'release_ledger_execution_id'])) OR\
                    (table_name='data_export_intents' AND column_name=ANY(ARRAY[\
                      'state','artifact_ref','artifact_digest','watermark_digest','signature_digest',\
                      'worm_receipt_ref','worm_receipt_digest','completion_adapter_receipt',\
                      'completed_at','completion_action_hash','completion_ledger_execution_id'])) OR\
                    (table_name='data_evidence_outbox' AND column_name=ANY(ARRAY[\
                      'state','delivery_receipt','delivered_at']))\
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
        || row.try_get::<i64, _>("base_grant_count")? != 26
        || row.try_get::<bool, _>("unexpected_update_column")?
        || row.try_get::<i64, _>("update_column_count")? != 39
    {
        return Err("DATA_GOVERNANCE_DATABASE_ROLE_UNSAFE".into());
    }
    Ok(())
}

fn database_options(
    value: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = Url::parse(value)?;
    let mut query = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized = key.to_ascii_lowercase();
        if key.as_ref() != normalized
            || value.is_empty()
            || query.insert(normalized, value.into_owned()).is_some()
        {
            return Err("DATA_GOVERNANCE_DATABASE_URL_INVALID".into());
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
            !matches!(key.as_str(), "sslmode" | "connect_timeout" | "application_name")
        })
        || query.get("sslmode").map(String::as_str) != Some("verify-full")
        || query.get("application_name").map(String::as_str)
            != Some("agenttrust-data-governance")
    {
        return Err("DATA_GOVERNANCE_DATABASE_URL_INVALID".into());
    }
    Ok(PgConnectOptions::new()
        .host(parsed.host_str().ok_or("DATA_GOVERNANCE_DATABASE_HOST_MISSING")?)
        .port(parsed.port().unwrap_or(5432))
        .username(expected_role)
        .password(password)
        .database(database)
        .application_name("agenttrust-data-governance")
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
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .identity(identity)
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .pool_idle_timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(8)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("agenttrust-data-governance/1")
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
        return Err("DATA_GOVERNANCE_SECRET_FILE_INVALID".into());
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
    let allowed = 0o400 | if metadata.gid() == effective_gid { 0o040 } else { 0 };
    let readable = (metadata.uid() == effective_uid && mode & 0o400 != 0)
        || (metadata.gid() == effective_gid && mode & 0o040 != 0);
    if !readable || mode & !allowed != 0 {
        return Err(format!("{name}_PERMISSIONS_UNSAFE").into());
    }
    Ok(path)
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
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let parsed = Uuid::parse_str(&raw)?;
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

fn required_mtls_identity(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    let san_value = value.strip_prefix("DNS:").or_else(|| value.strip_prefix("URI:"));
    if value.is_empty()
        || value.len() > 256
        || san_value.is_none_or(str::is_empty)
        || value.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn config_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

fn required_i64(
    name: &str,
    minimum: i64,
    maximum: i64,
) -> Result<i64, Box<dyn std::error::Error>> {
    let raw = env::var(name)?;
    let value = raw.parse::<i64>()?;
    if value < minimum || value > maximum || value.to_string() != raw {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_exact_port(name: &str, expected: u16) -> Result<u16, Box<dyn std::error::Error>> {
    let value = required_i64(name, 1, 65_535)?;
    if value != i64::from(expected) {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(expected)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let values = env::var(name)?.split(',').map(str::to_string).collect::<BTreeSet<_>>();
    if values.is_empty() || values.len() > 128 || values.iter().any(|value| {
        value.is_empty()
            || value.len() > 512
            || !(value.starts_with("DNS:") || value.starts_with("URI:"))
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
    }) {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(values)
}
