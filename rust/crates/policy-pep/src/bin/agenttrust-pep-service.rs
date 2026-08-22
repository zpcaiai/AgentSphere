use agent_trust_policy_pep::activation::PolicyBundleKeyring;
use agent_trust_policy_pep::authority::{PepAuthority, read_signing_key};
use agent_trust_policy_pep::governance::HumanPrincipalVerifier;
use agent_trust_policy_pep::postgres::PostgresPepStore;
use agent_trust_policy_pep::server::{PepServerConfig, TokenBindingPepAuthorizer, serve};
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
    let database_url = read_secret("AGENT_TRUST_PEP_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_PEP_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_PEP_DATABASE_CA_FILE", false)?;
    let expected_role = required_env("AGENT_TRUST_PEP_DATABASE_EXPECTED_ROLE")?;
    if !database_role(&expected_role) {
        return Err("PEP_DATABASE_ROLE_INVALID".into());
    }
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect_with(validate_database_url(
            &database_url,
            &database_password,
            &database_ca,
            &expected_role,
        )?)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;
    let store = Arc::new(PostgresPepStore::new(pool));
    let bindings_file = required_file("AGENT_TRUST_PEP_AUTHORITY_BINDINGS_FILE", true)?;
    let authority = Arc::new(PepAuthority::from_bindings(
        store,
        PepAuthority::bindings_from_file(&bindings_file)?,
        required_identifier("AGENT_TRUST_PEP_ISSUER")?,
        required_identifier("AGENT_TRUST_PEP_KEY_ID")?,
        read_signing_key(&required_file("AGENT_TRUST_PEP_PRIVATE_KEY_FILE", true)?)?,
        PolicyBundleKeyring::from_file(&required_file(
            "AGENT_TRUST_PEP_POLICY_BUNDLE_KEYRING_FILE",
            false,
        )?)?,
    )?);
    let identities = parse_identities(&required_env("AGENT_TRUST_PEP_CLIENT_IDENTITIES")?)?;
    let token_bindings = required_file("AGENT_TRUST_PEP_TOKEN_BINDINGS_FILE", true)?;
    let authorizer = Arc::new(TokenBindingPepAuthorizer::from_file(
        &token_bindings,
        &identities,
    )?);
    let human_principals = Arc::new(HumanPrincipalVerifier::from_file(
        required_file("AGENT_TRUST_PEP_HUMAN_ASSERTION_KEYRING_FILE", false)?,
        required_identifier("AGENT_TRUST_PEP_HUMAN_ASSERTION_AUDIENCE")?,
        required_env("AGENT_TRUST_PEP_HUMAN_ASSERTION_MAX_AUTHENTICATION_AGE_SECONDS")?
            .parse::<i64>()?,
        required_boolean("AGENT_TRUST_PEP_QUERY_REQUIRE_STRONG_AUTH")?,
    )?);
    if !authority.ready().await || !human_principals.ready() {
        return Err("PEP_AUTHORITIES_NOT_READY".into());
    }
    serve(
        PepServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_PEP_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file("AGENT_TRUST_PEP_TLS_CERTIFICATE_FILE", false)?,
            tls_private_key_file: required_file("AGENT_TRUST_PEP_TLS_PRIVATE_KEY_FILE", true)?,
            client_identities: identities,
        },
        authority,
        authorizer,
        human_principals,
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
            return Err("PEP_DATABASE_URL_INVALID".into());
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
        return Err("PEP_DATABASE_URL_INVALID".into());
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
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,\
                current_setting('search_path') AS search_path,\
                current_schemas(false)::text AS resolved_schemas,\
                current_setting('row_security') AS row_security,\
                has_schema_privilege(current_user,'public','CREATE') AS can_create,\
                has_table_privilege(current_user,'public.pep_authorization_requests','DELETE') AS can_delete_requests,\
                has_table_privilege(current_user,'public.pep_policy_decisions','DELETE') AS can_delete_decisions,\
                has_table_privilege(current_user,'public.pep_execution_authorizations','DELETE') AS can_delete_authorizations,\
                has_table_privilege(current_user,'public.pep_human_assertion_uses','DELETE') AS can_delete_assertions,\
                has_table_privilege(current_user,'public.pep_governance_evidence','DELETE') AS can_delete_governance_evidence,\
                has_table_privilege(current_user,'public.pep_evidence_outbox','DELETE') AS can_delete_evidence_outbox,\
                has_table_privilege(current_user,'public.pep_policy_bundle_artifacts','DELETE') AS can_delete_bundle_artifacts,\
                has_table_privilege(current_user,'public.pep_policy_activation_requests','DELETE') AS can_delete_activation_requests,\
                has_table_privilege(current_user,'public.pep_active_policy_bundles','DELETE') AS can_delete_active_bundles,\
                has_table_privilege(current_user,'public.pep_policy_activation_evidence','DELETE') AS can_delete_activation_evidence,\
                has_table_privilege(current_user,'public.pep_policy_activation_outbox','DELETE') AS can_delete_activation_outbox,\
                has_table_privilege(current_user,'public.pep_authorization_requests','INSERT') AS can_insert_requests,\
                has_table_privilege(current_user,'public.pep_policy_decisions','INSERT') AS can_insert_decisions,\
                has_table_privilege(current_user,'public.pep_execution_authorizations','INSERT') AS can_insert_authorizations,\
                has_table_privilege(current_user,'public.pep_human_assertion_uses','INSERT') AS can_insert_assertions,\
                has_table_privilege(current_user,'public.pep_governance_evidence','INSERT') AS can_insert_governance_evidence,\
                has_table_privilege(current_user,'public.pep_evidence_outbox','INSERT') AS can_insert_evidence_outbox,\
                has_table_privilege(current_user,'public.pep_human_assertion_uses','SELECT') AS can_select_assertions,\
                has_table_privilege(current_user,'public.pep_governance_evidence','SELECT') AS can_select_governance_evidence,\
                has_table_privilege(current_user,'public.pep_evidence_outbox','SELECT') AS can_select_evidence_outbox,\
                has_table_privilege(current_user,'public.pep_policy_bundle_artifacts','SELECT,INSERT') AS can_use_bundle_artifacts,\
                has_table_privilege(current_user,'public.pep_policy_activation_requests','SELECT,INSERT') AS can_use_activation_requests,\
                has_table_privilege(current_user,'public.pep_active_policy_bundles','SELECT,INSERT') AS can_use_active_bundles,\
                has_table_privilege(current_user,'public.pep_policy_activation_evidence','SELECT,INSERT') AS can_use_activation_evidence,\
                has_table_privilege(current_user,'public.pep_policy_activation_outbox','SELECT,INSERT') AS can_use_activation_outbox,\
                has_table_privilege(current_user,'public.pep_policy_bundle_artifacts','UPDATE') AS can_update_bundle_artifacts,\
                has_table_privilege(current_user,'public.pep_policy_activation_requests','UPDATE') AS can_update_activation_requests,\
                has_table_privilege(current_user,'public.pep_active_policy_bundles','UPDATE') AS can_update_active_bundles,\
                has_table_privilege(current_user,'public.pep_policy_activation_evidence','UPDATE') AS can_update_activation_evidence,\
                has_table_privilege(current_user,'public.pep_policy_activation_outbox','UPDATE') AS can_update_activation_outbox,\
                has_table_privilege(current_user,'public.pep_authorization_requests','UPDATE') AS can_update_requests,\
                has_table_privilege(current_user,'public.pep_policy_decisions','UPDATE') AS can_update_decisions,\
                has_table_privilege(current_user,'public.pep_execution_authorizations','UPDATE') AS can_update_authorizations,\
                has_table_privilege(current_user,'public.pep_human_assertion_uses','UPDATE') AS can_update_assertions,\
                has_table_privilege(current_user,'public.pep_governance_evidence','UPDATE') AS can_update_governance_evidence,\
                has_table_privilege(current_user,'public.pep_evidence_outbox','UPDATE') AS can_update_evidence_outbox \
         FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await?;
    if row.try_get::<String, _>("role_name")? != expected_role
        || row.try_get::<bool, _>("rolsuper")?
        || row.try_get::<bool, _>("rolbypassrls")?
        || row.try_get::<bool, _>("rolcreatedb")?
        || row.try_get::<bool, _>("rolcreaterole")?
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_delete_requests")?
        || row.try_get::<bool, _>("can_delete_decisions")?
        || row.try_get::<bool, _>("can_delete_authorizations")?
        || row.try_get::<bool, _>("can_delete_assertions")?
        || row.try_get::<bool, _>("can_delete_governance_evidence")?
        || row.try_get::<bool, _>("can_delete_evidence_outbox")?
        || row.try_get::<bool, _>("can_delete_bundle_artifacts")?
        || row.try_get::<bool, _>("can_delete_activation_requests")?
        || row.try_get::<bool, _>("can_delete_active_bundles")?
        || row.try_get::<bool, _>("can_delete_activation_evidence")?
        || row.try_get::<bool, _>("can_delete_activation_outbox")?
        || !row.try_get::<bool, _>("can_insert_requests")?
        || !row.try_get::<bool, _>("can_insert_decisions")?
        || !row.try_get::<bool, _>("can_insert_authorizations")?
        || !row.try_get::<bool, _>("can_insert_assertions")?
        || !row.try_get::<bool, _>("can_insert_governance_evidence")?
        || !row.try_get::<bool, _>("can_insert_evidence_outbox")?
        || !row.try_get::<bool, _>("can_select_assertions")?
        || !row.try_get::<bool, _>("can_select_governance_evidence")?
        || !row.try_get::<bool, _>("can_select_evidence_outbox")?
        || !row.try_get::<bool, _>("can_use_bundle_artifacts")?
        || !row.try_get::<bool, _>("can_use_activation_requests")?
        || !row.try_get::<bool, _>("can_use_active_bundles")?
        || !row.try_get::<bool, _>("can_use_activation_evidence")?
        || !row.try_get::<bool, _>("can_use_activation_outbox")?
        || row.try_get::<bool, _>("can_update_bundle_artifacts")?
        || row.try_get::<bool, _>("can_update_activation_requests")?
        || row.try_get::<bool, _>("can_update_active_bundles")?
        || row.try_get::<bool, _>("can_update_activation_evidence")?
        || row.try_get::<bool, _>("can_update_activation_outbox")?
        || !row.try_get::<bool, _>("can_update_requests")?
        || row.try_get::<bool, _>("can_update_decisions")?
        || row.try_get::<bool, _>("can_update_authorizations")?
        || row.try_get::<bool, _>("can_update_assertions")?
        || row.try_get::<bool, _>("can_update_governance_evidence")?
        || row.try_get::<bool, _>("can_update_evidence_outbox")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("PEP_DATABASE_ROLE_UNSAFE".into());
    }
    let expected_activation_update_columns = [
        ("pep_policy_activation_requests", "state"),
        ("pep_policy_activation_requests", "claim_owner"),
        ("pep_policy_activation_requests", "claim_expires_at"),
        ("pep_policy_activation_requests", "pdp_ack_digest"),
        ("pep_policy_activation_requests", "pdp_ack_body"),
        ("pep_policy_activation_requests", "response_digest"),
        ("pep_policy_activation_requests", "response_body"),
        ("pep_policy_activation_requests", "completed_at"),
        ("pep_policy_activation_requests", "updated_at"),
        ("pep_active_policy_bundles", "activation_id"),
        ("pep_active_policy_bundles", "policy_id"),
        ("pep_active_policy_bundles", "sequence"),
        ("pep_active_policy_bundles", "bundle_digest"),
        ("pep_active_policy_bundles", "policy_version"),
        ("pep_active_policy_bundles", "pdp_ack_digest"),
        ("pep_active_policy_bundles", "activated_at"),
    ]
    .into_iter()
    .map(|(table, column)| (table.to_string(), column.to_string()))
    .collect::<BTreeSet<_>>();
    let actual_activation_update_columns = sqlx::query(
        "SELECT table_name,column_name FROM information_schema.column_privileges \
         WHERE grantee=current_user AND table_schema='public' AND privilege_type='UPDATE' \
           AND table_name IN ('pep_policy_bundle_artifacts','pep_policy_activation_requests',\
                              'pep_active_policy_bundles','pep_policy_activation_evidence',\
                              'pep_policy_activation_outbox')",
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
    if actual_activation_update_columns != expected_activation_update_columns {
        return Err("PEP_DATABASE_ACTIVATION_GRANTS_UNSAFE".into());
    }
    Ok(())
}

fn parse_args<I: IntoIterator<Item = String>>(
    arguments: I,
) -> Result<Arguments, Box<dyn std::error::Error>> {
    let mut listen = "127.0.0.1".to_string();
    let mut port = 8086_u16;
    let mut management_listen = "127.0.0.1".to_string();
    let mut management_port = 9096_u16;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or("PEP_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("PEP_ARGUMENTS_INVALID".into()),
        }
    }
    if port == 0 || management_port == 0 || port == management_port {
        return Err("PEP_ARGUMENTS_INVALID".into());
    }
    let data = format!("{listen}:{port}").parse::<SocketAddr>()?;
    let management = format!("{management_listen}:{management_port}").parse::<SocketAddr>()?;
    if !(management.ip().is_loopback() || management.ip().is_unspecified()) {
        return Err("PEP_MANAGEMENT_LISTENER_INVALID".into());
    }
    Ok(Arguments { data, management })
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name}_REQUIRED").into())
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
    {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn required_boolean(name: &str) -> Result<bool, Box<dyn std::error::Error>> {
    match required_env(name)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("{name}_INVALID").into()),
    }
}

fn database_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || *byte == b'_')
}

fn required_file(name: &str, private: bool) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute() || !secure_file(&path, private)? {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(path)
}

fn read_secret(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    let value = std::fs::read_to_string(path)?;
    let value = value.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') || value.len() > 65_536 {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value.to_string())
}

fn parse_identities(value: &str) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let values = value
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if values.is_empty()
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 512
                || !(value.starts_with("DNS:") || value.starts_with("URI:"))
        })
    {
        return Err("PEP_CLIENT_IDENTITIES_INVALID".into());
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
        let allowed = 0o400 | if metadata.gid() == gid { 0o040 } else { 0 };
        ((metadata.uid() == uid && mode & 0o400 != 0)
            || (metadata.gid() == gid && mode & 0o040 != 0))
            && mode & !allowed == 0
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
fn secure_file(_: &Path, _: bool) -> Result<bool, std::io::Error> {
    Ok(false)
}
