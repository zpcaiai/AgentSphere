use agent_trust_contracts::{AgentInstanceId, ToolId, ToolVersion};
use agent_trust_pack_marketplace::authority::{
    MarketplaceAuthorityConfig, MarketplaceExecutor, MarketplaceIngressAuthority,
    PostgresMarketplaceAuthorityStore, ReleaseGateKeyring,
};
use agent_trust_pack_marketplace::principal::HumanPrincipalKeyring;
use agent_trust_pack_marketplace::server::{
    HttpMarketplaceOrchestrator, MarketplaceServerConfig, MarketplaceTokenAuthorizer, router, serve,
};
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
        eprintln!("PACK_MARKETPLACE_SERVICE_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = read_secret_file("AGENT_TRUST_MARKETPLACE_DATABASE_URL_FILE", 16, 16_384)?;
    let database_password =
        read_secret_file("AGENT_TRUST_MARKETPLACE_DATABASE_PASSWORD_FILE", 16, 8_192)?;
    let database_ca = required_path("AGENT_TRUST_MARKETPLACE_DATABASE_CA_FILE")?;
    let expected_role = required_identifier("AGENT_TRUST_MARKETPLACE_DATABASE_EXPECTED_ROLE")?;
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
    let store = PostgresMarketplaceAuthorityStore::new(pool);

    let outbound = outbound_client(
        &required_path("AGENT_TRUST_MARKETPLACE_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_MARKETPLACE_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_MARKETPLACE_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let orchestrator = Arc::new(HttpMarketplaceOrchestrator::new(
        outbound,
        required_url("AGENT_TRUST_MARKETPLACE_ORCHESTRATOR_ENDPOINT")?,
        required_private_path("AGENT_TRUST_MARKETPLACE_ORCHESTRATOR_TOKEN_FILE")?,
    )?);
    let ingress_subject = required_identifier("AGENT_TRUST_MARKETPLACE_INGRESS_SUBJECT")?;
    let authority = MarketplaceIngressAuthority::new(
        store.clone(),
        orchestrator,
        MarketplaceAuthorityConfig {
            service_agent_id: AgentInstanceId(required_uuid(
                "AGENT_TRUST_MARKETPLACE_AGENT_INSTANCE_ID",
            )?),
            organization_id: required_identifier("AGENT_TRUST_MARKETPLACE_ORGANIZATION_ID")?,
            agent_version: required_identifier("AGENT_TRUST_MARKETPLACE_AGENT_VERSION")?,
            region: required_identifier("AGENT_TRUST_MARKETPLACE_REGION")?,
            tool_id: ToolId(required_identifier("AGENT_TRUST_MARKETPLACE_TOOL_ID")?),
            tool_version: ToolVersion(required_identifier("AGENT_TRUST_MARKETPLACE_TOOL_VERSION")?),
            credential_profile: required_identifier(
                "AGENT_TRUST_MARKETPLACE_EXECUTOR_CREDENTIAL_PROFILE",
            )?,
            service_subject: ingress_subject.clone(),
        },
    )?;
    let release_gate_keyring = Arc::new(ReleaseGateKeyring::from_file(
        &required_path("AGENT_TRUST_MARKETPLACE_RELEASE_GATE_KEYRING_FILE")?,
        &required_identifier("AGENT_TRUST_MARKETPLACE_RELEASE_GATE_ID")?,
    )?);
    let executor = MarketplaceExecutor::new(store, release_gate_keyring);
    let allowed_identities = required_identities("AGENT_TRUST_MARKETPLACE_CLIENT_IDENTITIES")?;
    let tokens = Arc::new(MarketplaceTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_MARKETPLACE_TOKEN_BINDINGS_FILE")?,
        &allowed_identities,
    )?);
    let audience = required_identifier("AGENT_TRUST_HUMAN_PRINCIPAL_AUDIENCE")?;
    let principal_keyring = Arc::new(HumanPrincipalKeyring::from_file(
        &required_path("AGENT_TRUST_HUMAN_PRINCIPAL_KEYRING_FILE")?,
        &audience,
    )?);
    let executor_subject = required_identifier("AGENT_TRUST_MARKETPLACE_EXECUTOR_SUBJECT")?;
    let query_subject = required_identifier("AGENT_TRUST_MARKETPLACE_QUERY_SUBJECT")?;
    let maximum_authentication_age_seconds = required_i64(
        "AGENT_TRUST_MARKETPLACE_MAXIMUM_AUTHENTICATION_AGE_SECONDS",
        60,
        86_400,
    )?;
    let application = router(
        authority.clone(),
        executor,
        tokens,
        principal_keyring,
        ingress_subject.clone(),
        executor_subject.clone(),
        query_subject.clone(),
        maximum_authentication_age_seconds,
    );
    let listen: IpAddr = env::var("AGENT_TRUST_MARKETPLACE_LISTEN_ADDRESS")?.parse()?;
    let management_listen: IpAddr =
        env::var("AGENT_TRUST_MARKETPLACE_MANAGEMENT_LISTEN_ADDRESS")?.parse()?;
    serve(
        MarketplaceServerConfig {
            data_address: SocketAddr::new(
                listen,
                required_i64("AGENT_TRUST_MARKETPLACE_PORT", 1, 65_535)? as u16,
            ),
            management_address: SocketAddr::new(
                management_listen,
                required_i64("AGENT_TRUST_MARKETPLACE_MANAGEMENT_PORT", 1, 65_535)? as u16,
            ),
            tls_ca_file: required_path("AGENT_TRUST_MARKETPLACE_TLS_CA_FILE")?,
            tls_certificate_file: required_path("AGENT_TRUST_MARKETPLACE_TLS_CERTIFICATE_FILE")?,
            tls_private_key_file: required_private_path(
                "AGENT_TRUST_MARKETPLACE_TLS_PRIVATE_KEY_FILE",
            )?,
            allowed_client_identities: allowed_identities,
            ingress_subject,
            executor_subject,
            query_subject,
            maximum_authentication_age_seconds,
        },
        application,
        authority,
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
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND table_name LIKE 'marketplace_%' \
                  AND NOT ((table_name=ANY(ARRAY[\
                    'marketplace_publishers','marketplace_publisher_keys','marketplace_pack_names',\
                    'marketplace_tenant_catalog','marketplace_releases','marketplace_installations',\
                    'marketplace_upgrade_plans','marketplace_canary_results','marketplace_revocations',\
                    'marketplace_resource_versions','marketplace_principal_assertion_replay',\
                    'marketplace_action_ingress','marketplace_authority_executions']) \
                    AND privilege_type IN ('SELECT','INSERT')) \
                   OR (table_name=ANY(ARRAY['marketplace_evidence_events','marketplace_evidence_outbox']) \
                    AND privilege_type='INSERT'))) AS unexpected_table_grant,\
                EXISTS (SELECT 1 FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND table_name<>ALL(ARRAY[\
                    'marketplace_publishers','marketplace_publisher_keys','marketplace_pack_names',\
                    'marketplace_tenant_catalog','marketplace_releases','marketplace_installations',\
                    'marketplace_upgrade_plans','marketplace_canary_results','marketplace_revocations',\
                    'marketplace_resource_versions','marketplace_principal_assertion_replay',\
                    'marketplace_action_ingress','marketplace_authority_executions',\
                    'marketplace_evidence_events','marketplace_evidence_outbox'])) \
                  AS cross_domain_table_grant,\
                EXISTS (SELECT 1 FROM information_schema.role_column_grants WHERE grantee=current_user \
                  AND table_schema='public' AND table_name LIKE 'marketplace_%' \
                  AND privilege_type='UPDATE' AND NOT (\
                    (table_name='marketplace_publishers' AND column_name=ANY(ARRAY[\
                      'trust_status','verified_by','verified_at','revoked_at','updated_at'])) OR \
                    (table_name='marketplace_publisher_keys' AND column_name=ANY(ARRAY[\
                      'status','revoked_at'])) OR \
                    (table_name='marketplace_tenant_catalog' AND column_name=ANY(ARRAY[\
                      'control_plane_version','region','entitlements','allowed_compatibility',\
                      'minimum_publisher_trust','maximum_risk','configured_by','updated_at'])) OR \
                    (table_name='marketplace_releases' AND column_name=ANY(ARRAY[\
                      'review_status','reviewed_by','review_digest','published_at','revoked_at','updated_at'])) OR \
                    (table_name='marketplace_installations' AND column_name=ANY(ARRAY[\
                      'state','approved_by','approval_digest','artifact_receipt_digest',\
                      'previous_installation_id','production_certificate_digest','deactivation_reason_digest',\
                      'approved_at','installed_at','activated_at','deactivated_at','revoked_at','updated_at'])) OR \
                    (table_name='marketplace_upgrade_plans' AND column_name=ANY(ARRAY[\
                      'state','rollback_reason_digest','completed_at','rolled_back_at','updated_at'])) OR \
                    (table_name='marketplace_resource_versions' AND column_name=ANY(ARRAY[\
                      'resource_version','action_hash','policy_decision_id','ledger_entry_id',\
                      'ledger_execution_id','fence_digest','updated_at'])) OR \
                    (table_name='marketplace_action_ingress' AND column_name=ANY(ARRAY[\
                      'state','receipt','updated_at'])) OR \
                    (table_name='marketplace_authority_executions' AND column_name=ANY(ARRAY[\
                      'state','safe_result','safe_result_digest','stable_error','updated_at']))\
                  )) AS unexpected_update_column,\
                EXISTS (SELECT 1 FROM information_schema.role_routine_grants WHERE grantee=current_user \
                  AND routine_schema='public' AND privilege_type='EXECUTE') AS can_execute_function,\
                (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type IN ('SELECT','INSERT') \
                  AND table_name=ANY(ARRAY[\
                   'marketplace_publishers','marketplace_publisher_keys','marketplace_pack_names',\
                   'marketplace_tenant_catalog','marketplace_releases','marketplace_installations',\
                   'marketplace_upgrade_plans','marketplace_canary_results','marketplace_revocations',\
                   'marketplace_resource_versions','marketplace_principal_assertion_replay',\
                   'marketplace_action_ingress','marketplace_authority_executions'])) AS base_table_grant_count,\
                (SELECT count(*) FROM information_schema.role_table_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type='INSERT' \
                  AND table_name=ANY(ARRAY['marketplace_evidence_events','marketplace_evidence_outbox'])) \
                  AS evidence_table_grant_count,\
                (SELECT count(*) FROM information_schema.role_column_grants WHERE grantee=current_user \
                  AND table_schema='public' AND privilege_type='UPDATE' AND (\
                    (table_name='marketplace_publishers' AND column_name=ANY(ARRAY[\
                      'trust_status','verified_by','verified_at','revoked_at','updated_at'])) OR \
                    (table_name='marketplace_publisher_keys' AND column_name=ANY(ARRAY['status','revoked_at'])) OR \
                    (table_name='marketplace_tenant_catalog' AND column_name=ANY(ARRAY[\
                      'control_plane_version','region','entitlements','allowed_compatibility',\
                      'minimum_publisher_trust','maximum_risk','configured_by','updated_at'])) OR \
                    (table_name='marketplace_releases' AND column_name=ANY(ARRAY[\
                      'review_status','reviewed_by','review_digest','published_at','revoked_at','updated_at'])) OR \
                    (table_name='marketplace_installations' AND column_name=ANY(ARRAY[\
                      'state','approved_by','approval_digest','artifact_receipt_digest',\
                      'previous_installation_id','production_certificate_digest','deactivation_reason_digest',\
                      'approved_at','installed_at','activated_at','deactivated_at','revoked_at','updated_at'])) OR \
                    (table_name='marketplace_upgrade_plans' AND column_name=ANY(ARRAY[\
                      'state','rollback_reason_digest','completed_at','rolled_back_at','updated_at'])) OR \
                    (table_name='marketplace_resource_versions' AND column_name=ANY(ARRAY[\
                      'resource_version','action_hash','policy_decision_id','ledger_entry_id',\
                      'ledger_execution_id','fence_digest','updated_at'])) OR \
                    (table_name='marketplace_action_ingress' AND column_name=ANY(ARRAY[\
                      'state','receipt','updated_at'])) OR \
                    (table_name='marketplace_authority_executions' AND column_name=ANY(ARRAY[\
                      'state','safe_result','safe_result_digest','stable_error','updated_at']))\
                  )) AS update_column_grant_count \
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
        || row.try_get::<bool, _>("unexpected_table_grant")?
        || row.try_get::<bool, _>("cross_domain_table_grant")?
        || row.try_get::<bool, _>("unexpected_update_column")?
        || row.try_get::<bool, _>("can_execute_function")?
        || row.try_get::<i64, _>("base_table_grant_count")? != 26
        || row.try_get::<i64, _>("evidence_table_grant_count")? != 2
        || row.try_get::<i64, _>("update_column_grant_count")? != 54
    {
        return Err("MARKETPLACE_DATABASE_ROLE_UNSAFE".into());
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
            return Err("MARKETPLACE_DATABASE_URL_INVALID".into());
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
        return Err("MARKETPLACE_DATABASE_URL_INVALID".into());
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
        return Err("MARKETPLACE_REQUIRED_FILE_INVALID".into());
    }
    Ok(path)
}

fn required_private_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env::var(name)?);
    if !path.is_absolute() || !secure_file(&path, true)? {
        return Err("MARKETPLACE_PRIVATE_FILE_INVALID".into());
    }
    Ok(path)
}

fn secure_file(path: &Path, private: bool) -> Result<bool, Box<dyn std::error::Error>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > 1_048_576
    {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let mode = metadata.permissions().mode() & 0o777;
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
        if !access {
            return Ok(false);
        }
    }
    #[cfg(not(unix))]
    if private {
        return Ok(false);
    }
    Ok(true)
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
        return Err("MARKETPLACE_SECRET_FILE_INVALID".into());
    }
    Ok(secret.to_string())
}

fn required_url(name: &str) -> Result<url::Url, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    let url = url::Url::parse(&value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("MARKETPLACE_URL_INVALID".into());
    }
    Ok(url)
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || b"._:/@-".contains(&byte)))
    {
        return Err("MARKETPLACE_IDENTIFIER_INVALID".into());
    }
    Ok(value)
}

fn required_uuid(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = env::var(name)?;
    let parsed = uuid::Uuid::parse_str(&value)?;
    if parsed.to_string() != value {
        return Err("MARKETPLACE_UUID_INVALID".into());
    }
    Ok(value)
}

fn required_identities(name: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let values = env::var(name)?;
    let identities = values
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if identities.is_empty()
        || identities.iter().any(|identity| {
            identity.len() > 512
                || !(identity.starts_with("DNS:") || identity.starts_with("URI:"))
                || identity.split_once(':').is_none_or(|(_, value)| {
                    value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_graphic())
                })
        })
    {
        return Err("MARKETPLACE_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(identities)
}

fn required_i64(name: &str, minimum: i64, maximum: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value = env::var(name)?.parse::<i64>()?;
    if !(minimum..=maximum).contains(&value) {
        return Err("MARKETPLACE_INTEGER_INVALID".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_files_accept_csi_group_read_but_reject_other_access() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "agenttrust-marketplace-private-file-{}",
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
}
