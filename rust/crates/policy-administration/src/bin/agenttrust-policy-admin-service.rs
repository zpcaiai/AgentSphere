use agent_trust_contracts::{AgentInstanceId, ToolId, ToolVersion};
use agent_trust_policy_administration::authority::{
    HttpPepPolicyActivationClient, PolicyAuthorityConfig, PolicyExecutor, PolicyIngressAuthority,
    PostgresPolicyAuthorityStore,
};
use agent_trust_policy_administration::principal::HumanPrincipalKeyring;
use agent_trust_policy_administration::server::{
    HttpPolicyOrchestrator, PolicyServerConfig, PolicyTokenAuthorizer, router, serve,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use reqwest::{Certificate, Identity};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("POLICY_ADMIN_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = read_secret_file("AGENT_TRUST_POLICY_DATABASE_URL_FILE", 16, 16_384)?;
    let database_password =
        read_secret_file("AGENT_TRUST_POLICY_DATABASE_PASSWORD_FILE", 16, 8_192)?;
    let database_ca = required_path("AGENT_TRUST_POLICY_DATABASE_CA_FILE")?;
    let expected_role = required_identifier("AGENT_TRUST_POLICY_DATABASE_EXPECTED_ROLE")?;
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
    let store = PostgresPolicyAuthorityStore::new(pool);

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_POLICY_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_POLICY_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_POLICY_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let pep_activation_verifying_key =
        read_verifying_key("AGENT_TRUST_POLICY_PEP_ACTIVATION_VERIFYING_KEY_FILE")?;
    let activation = Arc::new(HttpPepPolicyActivationClient::new(
        outbound.clone(),
        required_exact_url(
            "AGENT_TRUST_POLICY_PEP_ACTIVATION_ENDPOINT",
            "/v1/policies/activations",
        )?,
        required_private_path("AGENT_TRUST_POLICY_PEP_ACTIVATION_TOKEN_FILE")?,
        pep_activation_verifying_key,
    )?);
    let orchestrator = Arc::new(HttpPolicyOrchestrator::new(
        outbound,
        required_url("AGENT_TRUST_POLICY_ORCHESTRATOR_ENDPOINT")?,
        required_private_path("AGENT_TRUST_POLICY_ORCHESTRATOR_TOKEN_FILE")?,
    )?);
    let service_subject = required_identifier("AGENT_TRUST_POLICY_SERVICE_SUBJECT")?;
    let authority = PolicyIngressAuthority::new(
        store.clone(),
        orchestrator,
        PolicyAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_POLICY_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_POLICY_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_POLICY_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_POLICY_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_POLICY_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_POLICY_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_POLICY_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: service_subject.clone(),
        },
    )?;
    let signing_key = read_signing_key("AGENT_TRUST_POLICY_BUNDLE_SIGNING_PRIVATE_KEY_FILE")?;
    let executor = PolicyExecutor::new(
        store,
        required_identifier("AGENT_TRUST_POLICY_BUNDLE_SIGNING_KEY_ID")?,
        signing_key,
        activation,
        pep_activation_verifying_key,
    )?;
    let allowed_identities = required_identities("AGENT_TRUST_POLICY_CLIENT_IDENTITIES")?;
    let token_authorizer = PolicyTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_POLICY_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?;
    let managed_tenants = token_authorizer.tenants();
    let tokens = Arc::new(token_authorizer);
    let audience = required_identifier("AGENT_TRUST_HUMAN_PRINCIPAL_AUDIENCE")?;
    let keyring = Arc::new(HumanPrincipalKeyring::from_file(
        &required_path("AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE")?,
        &audience,
    )?);
    let maximum_authentication_age_seconds = required_i64(
        "AGENT_TRUST_POLICY_MAXIMUM_AUTHENTICATION_AGE_SECONDS",
        60,
        86_400,
    )?;
    let application = router(
        authority.clone(),
        executor.clone(),
        tokens,
        keyring,
        service_subject.clone(),
        maximum_authentication_age_seconds,
    );
    let listen: IpAddr = env::var("AGENT_TRUST_POLICY_LISTEN_ADDRESS")?.parse()?;
    let management_listen: IpAddr =
        env::var("AGENT_TRUST_POLICY_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    serve(
        PolicyServerConfig {
            data_address: SocketAddr::new(
                listen,
                required_i64("AGENT_TRUST_POLICY_PORT", 1, 65_535)? as u16,
            ),
            management_address: SocketAddr::new(
                management_listen,
                required_i64("AGENT_TRUST_POLICY_MANAGEMENT_PORT", 1, 65_535)? as u16,
            ),
            tls_ca_file: required_path("AGENT_TRUST_POLICY_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_POLICY_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path("AGENT_TRUST_POLICY_TLS_PRIVATE_KEY_FILE")?,
            allowed_client_identities: allowed_identities,
            service_subject,
            maximum_authentication_age_seconds,
            managed_tenants,
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
    expected_role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
                rolreplication,rolinherit,rolcanlogin,current_setting('search_path') AS search_path,\
                current_schemas(true)::text AS schemas,current_setting('row_security') AS row_security,\
                has_schema_privilege(current_user,'public','CREATE') AS can_create,\
                has_database_privilege(current_user,current_database(),'TEMP') AS can_temp,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user\
                  AND table_schema='public' AND table_name LIKE 'policy_%' AND privilege_type='DELETE') AS can_delete,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user\
                  AND table_schema='public' AND table_name='policy_evidence_events' AND privilege_type='UPDATE') AS can_rewrite_evidence,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user\
                  AND table_schema='public' AND table_name='policy_evidence_outbox' AND privilege_type='UPDATE') AS can_publish_outbox \
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
        || row.try_get::<bool, _>("can_delete")?
        || row.try_get::<bool, _>("can_rewrite_evidence")?
        || row.try_get::<bool, _>("can_publish_outbox")?
    {
        return Err("POLICY_DATABASE_ROLE_UNSAFE".into());
    }
    let expected_table_grants = [
        ("policy_sources", "SELECT"),
        ("policy_sources", "INSERT"),
        ("policy_analysis_results", "SELECT"),
        ("policy_analysis_results", "INSERT"),
        ("policy_simulation_runs", "SELECT"),
        ("policy_simulation_runs", "INSERT"),
        ("policy_impact_reports", "SELECT"),
        ("policy_impact_reports", "INSERT"),
        ("policy_reviews", "SELECT"),
        ("policy_reviews", "INSERT"),
        ("policy_bundles", "SELECT"),
        ("policy_bundles", "INSERT"),
        ("policy_exceptions", "SELECT"),
        ("policy_exceptions", "INSERT"),
        ("policy_promotions", "SELECT"),
        ("policy_promotions", "INSERT"),
        ("policy_activation_intents", "SELECT"),
        ("policy_activation_intents", "INSERT"),
        ("policy_resource_versions", "SELECT"),
        ("policy_resource_versions", "INSERT"),
        ("policy_principal_assertion_replay", "SELECT"),
        ("policy_principal_assertion_replay", "INSERT"),
        ("policy_action_ingress", "SELECT"),
        ("policy_action_ingress", "INSERT"),
        ("policy_authority_executions", "SELECT"),
        ("policy_authority_executions", "INSERT"),
        ("policy_evidence_events", "SELECT"),
        ("policy_evidence_events", "INSERT"),
        ("policy_evidence_outbox", "INSERT"),
    ]
    .into_iter()
    .map(|(table, privilege)| (table.to_string(), privilege.to_string()))
    .collect::<BTreeSet<_>>();
    let actual_table_grants = sqlx::query(
        "SELECT table_name,privilege_type FROM information_schema.role_table_grants \
         WHERE grantee=current_user AND table_schema='public'",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("table_name")?,
            row.try_get::<String, _>("privilege_type")?,
        ))
    })
    .collect::<Result<BTreeSet<_>, sqlx::Error>>()?;
    let expected_update_columns = [
        ("policy_sources", "lifecycle_state"),
        ("policy_sources", "updated_at"),
        ("policy_bundles", "status"),
        ("policy_bundles", "deprecated_at"),
        ("policy_exceptions", "revoked_at"),
        ("policy_exceptions", "revocation_reason_digest"),
        ("policy_exceptions", "expired_at"),
        ("policy_promotions", "state"),
        ("policy_promotions", "completed_at"),
        ("policy_resource_versions", "resource_version"),
        ("policy_activation_intents", "state"),
        ("policy_activation_intents", "claim_owner"),
        ("policy_activation_intents", "claim_expires_at"),
        ("policy_activation_intents", "acknowledgement_digest"),
        ("policy_activation_intents", "acknowledgement"),
        ("policy_activation_intents", "updated_at"),
        ("policy_activation_intents", "activated_at"),
        ("policy_resource_versions", "action_hash"),
        ("policy_resource_versions", "ledger_execution_id"),
        ("policy_resource_versions", "fence_digest"),
        ("policy_resource_versions", "updated_at"),
        ("policy_action_ingress", "state"),
        ("policy_action_ingress", "receipt"),
        ("policy_action_ingress", "updated_at"),
        ("policy_authority_executions", "state"),
        ("policy_authority_executions", "safe_result"),
        ("policy_authority_executions", "safe_result_digest"),
        ("policy_authority_executions", "stable_error"),
        ("policy_authority_executions", "updated_at"),
    ]
    .into_iter()
    .map(|(table, column)| (table.to_string(), column.to_string()))
    .collect::<BTreeSet<_>>();
    let actual_update_columns = sqlx::query(
        "SELECT table_name,column_name FROM information_schema.column_privileges \
         WHERE grantee=current_user AND table_schema='public' AND privilege_type='UPDATE'",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| {
        Ok((
            row.try_get::<String, _>("table_name")?,
            row.try_get::<String, _>("column_name")?,
        ))
    })
    .collect::<Result<BTreeSet<_>, sqlx::Error>>()?;
    if actual_table_grants != expected_table_grants
        || actual_update_columns != expected_update_columns
    {
        return Err("POLICY_DATABASE_GRANTS_UNSAFE".into());
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
    let mut query = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized = key.to_ascii_lowercase();
        if key.as_ref() != normalized
            || value.is_empty()
            || query.insert(normalized, value.into_owned()).is_some()
        {
            return Err("POLICY_DATABASE_URL_INVALID".into());
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
        return Err("POLICY_DATABASE_URL_INVALID".into());
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
        return Err("POLICY_REQUIRED_FILE_INVALID".into());
    }
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, true)? {
        return Err("POLICY_PRIVATE_FILE_INVALID".into());
    }
    Ok(path)
}

fn read_secret_file(
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let value = std::fs::read_to_string(required_private_path(name)?)?;
    let secret = value.trim_end_matches(['\r', '\n']);
    if !(minimum..=maximum).contains(&secret.len())
        || secret.bytes().any(|byte| !byte.is_ascii_graphic())
        || value.len().saturating_sub(secret.len()) > 2
    {
        return Err("POLICY_SECRET_FILE_INVALID".into());
    }
    Ok(secret.to_string())
}

fn read_signing_key(name: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let mut raw = std::fs::read(required_private_path(name)?)?;
    while raw.last().is_some_and(|byte| matches!(byte, b'\r' | b'\n')) {
        raw.pop();
    }
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "POLICY_SIGNING_KEY_INVALID")?;
    let key = SigningKey::from_bytes(&bytes);
    raw.zeroize();
    Ok(key)
}

fn read_verifying_key(name: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let encoded = std::fs::read_to_string(required_path(name)?)?;
    let encoded = encoded.trim();
    let raw = URL_SAFE_NO_PAD.decode(encoded)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "POLICY_PEP_VERIFYING_KEY_INVALID")?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

fn required_exact_url(name: &str, path: &str) -> Result<url::Url, Box<dyn std::error::Error>> {
    let value = url::Url::parse(&env::var(name)?)?;
    if value.scheme() != "https"
        || value.host_str().is_none()
        || !value.username().is_empty()
        || value.password().is_some()
        || value.path() != path
        || value.query().is_some()
        || value.fragment().is_some()
    {
        return Err("POLICY_ENDPOINT_INVALID".into());
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
        return Err("POLICY_ENDPOINT_INVALID".into());
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
        return Err("POLICY_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if !uuid::Uuid::parse_str(&value).is_ok_and(|parsed| parsed.to_string() == value) {
        return Err("POLICY_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value: i64 = env::var(name)?.parse()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("POLICY_INTEGER_INVALID".into());
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
        return Err("POLICY_CLIENT_IDENTITIES_INVALID".into());
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
