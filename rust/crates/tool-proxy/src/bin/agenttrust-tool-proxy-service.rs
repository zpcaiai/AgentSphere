use agent_trust_contracts::TenantId;
use agent_trust_tool_proxy::production::{
    DeferredProductionAuditSink, HttpsRegistryClient, PostgresInvocationStore,
    ProductionToolProxyService, RegistrySnapshotKeyring, RegistryVerificationKey,
    SensitiveRegistryToken,
};
use agent_trust_tool_proxy::server::{
    TokenBindingToolProxyAuthorizer, ToolProxyServerConfig, ToolProxyServerDependencies, serve,
};
use agent_trust_tool_proxy::{
    CredentialAuthorityKeyring, CredentialAuthorityVerificationKey, HttpConnector, HttpOperation,
    HttpTargetProfile, HttpWorkloadCredentialConsumptionPort, PoolIsolationKey,
    ProxyAuthorizationVerificationKey, ProxyAuthorizationVerifier, ReqwestVaultLeaseTransport,
    SensitiveCredentialAuthorityToken, SensitiveVaultToken, ToolProxy, VaultLeaseProfile,
    VaultTargetSecretProvider, WorkloadCredentialConsumptionPort, is_public_target_ip,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const VERIFICATION_KEYS_SCHEMA: &str = "agenttrust.tool-proxy-verification-keys.v1";
const TARGET_PROFILES_SCHEMA: &str = "agenttrust.tool-proxy-target-profiles.v1";
const TARGET_PROFILE_KEY_USAGE: &str = "TOOL_PROXY_TARGET_PROFILES";

#[derive(Debug, PartialEq, Eq)]
struct Arguments {
    data: SocketAddr,
    management: SocketAddr,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyDocument {
    schema_version: String,
    keys: Vec<VerificationKeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyEntry {
    issuer: String,
    key_id: String,
    key_usages: Vec<String>,
    public_key_base64url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedTargetProfiles {
    schema_version: String,
    issuer: String,
    key_id: String,
    key_usage: String,
    profiles: Vec<TargetProfile>,
    signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetProfile {
    tenant_id: String,
    target_profile: String,
    credential_profile: String,
    executor_profile: String,
    lease_path: String,
    secret_field: String,
    base_url: String,
    pinned_addresses: Vec<String>,
    operations: BTreeMap<String, TargetOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetOperation {
    method: String,
    path: String,
    content_type: String,
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("TOOL_PROXY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_args(env::args().skip(1))?;
    let database_url = read_secret("AGENT_TRUST_TOOL_PROXY_DATABASE_URL_FILE")?;
    let database_password = read_secret("AGENT_TRUST_TOOL_PROXY_DATABASE_PASSWORD_FILE")?;
    let database_ca = required_file("AGENT_TRUST_TOOL_PROXY_DATABASE_CA_FILE", false)?;
    let expected_role = required_identifier("AGENT_TRUST_TOOL_PROXY_DATABASE_EXPECTED_ROLE")?;
    let connect = validate_database_url(&database_url, &database_ca, &database_password)?;
    let pool = PgPoolOptions::new()
        .min_connections(1)
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect)
        .await?;
    verify_database_posture(&pool, &expected_role).await?;

    let verification_keys = read_verification_keys(&required_file(
        "AGENT_TRUST_TOOL_PROXY_VERIFICATION_KEYS_FILE",
        false,
    )?)?;
    let authorization = Arc::new(ProxyAuthorizationVerifier::from_keys(
        verification_keys
            .iter()
            .filter(|key| key.key_usages.contains("PEP_EXECUTION_AUTHORIZATION"))
            .map(|key| ProxyAuthorizationVerificationKey {
                key_id: key.key_id.clone(),
                issuer: key.issuer.clone(),
                key: key.key,
            })
            .collect(),
    )?);
    let credential_keyring = CredentialAuthorityKeyring::new(
        verification_keys
            .iter()
            .filter(|key| {
                key.key_usages.contains("WORKLOAD_CREDENTIAL_BINDING")
                    || key.key_usages.contains("WORKLOAD_CREDENTIAL_CONSUMPTION")
            })
            .map(|key| CredentialAuthorityVerificationKey {
                key_id: key.key_id.clone(),
                issuer: key.issuer.clone(),
                key_usages: key
                    .key_usages
                    .iter()
                    .filter(|usage| {
                        matches!(
                            usage.as_str(),
                            "WORKLOAD_CREDENTIAL_BINDING" | "WORKLOAD_CREDENTIAL_CONSUMPTION"
                        )
                    })
                    .cloned()
                    .collect(),
                key: key.key,
            })
            .collect(),
    )?;
    let registry_keyring = RegistrySnapshotKeyring::new(
        verification_keys
            .iter()
            .filter(|key| key.key_usages.contains("REGISTRY_SNAPSHOT"))
            .map(|key| RegistryVerificationKey {
                publisher_id: key.issuer.clone(),
                key_id: key.key_id.clone(),
                key: key.key,
            })
            .collect(),
    )?;

    let outbound_certificate = required_file(
        "AGENT_TRUST_TOOL_PROXY_OUTBOUND_TLS_CERTIFICATE_FILE",
        false,
    )?;
    let outbound_private_key =
        required_file("AGENT_TRUST_TOOL_PROXY_OUTBOUND_TLS_PRIVATE_KEY_FILE", true)?;
    let registry_client = build_mtls_client(
        &required_file("AGENT_TRUST_TOOL_PROXY_REGISTRY_CA_FILE", false)?,
        &outbound_certificate,
        &outbound_private_key,
        Duration::from_secs(5),
        &BTreeMap::new(),
    )?;
    let registry = Arc::new(HttpsRegistryClient::new(
        strict_https_root(&required_env("AGENT_TRUST_TOOL_PROXY_REGISTRY_ENDPOINT")?)?,
        registry_client,
        SensitiveRegistryToken::new(
            read_secret("AGENT_TRUST_TOOL_PROXY_REGISTRY_TOKEN_FILE")?.to_string(),
        )?,
        registry_keyring,
    )?);
    let credential_client = build_mtls_client(
        &required_file("AGENT_TRUST_TOOL_PROXY_CREDENTIAL_AUTHORITY_CA_FILE", false)?,
        &outbound_certificate,
        &outbound_private_key,
        Duration::from_secs(5),
        &BTreeMap::new(),
    )?;
    let credentials = Arc::new(HttpWorkloadCredentialConsumptionPort::new(
        strict_https_root(&required_env(
            "AGENT_TRUST_TOOL_PROXY_CREDENTIAL_AUTHORITY_ENDPOINT",
        )?)?,
        credential_client,
        SensitiveCredentialAuthorityToken::new(
            read_secret("AGENT_TRUST_TOOL_PROXY_CREDENTIAL_AUTHORITY_TOKEN_FILE")?.to_string(),
        )?,
        credential_keyring,
    )?);

    let signed_profiles = read_and_verify_profiles(
        &required_file("AGENT_TRUST_TOOL_PROXY_TARGET_PROFILES_FILE", false)?,
        &verification_keys,
    )?;
    let (vault_profiles, connectors) = build_profiles(
        signed_profiles.profiles,
        &required_file("AGENT_TRUST_TOOL_PROXY_TARGET_CA_FILE", false)?,
        &outbound_certificate,
        &outbound_private_key,
    )?;
    let vault_client = build_mtls_client(
        &required_file("AGENT_TRUST_TOOL_PROXY_VAULT_CA_FILE", false)?,
        &outbound_certificate,
        &outbound_private_key,
        Duration::from_secs(10),
        &BTreeMap::new(),
    )?;
    let vault_transport = Arc::new(ReqwestVaultLeaseTransport::new(
        strict_https_root(&required_env("AGENT_TRUST_TOOL_PROXY_VAULT_ENDPOINT")?)?,
        SensitiveVaultToken::new(
            read_secret("AGENT_TRUST_TOOL_PROXY_VAULT_TOKEN_FILE")?.to_string(),
        )?,
        vault_client,
    )?);
    let secrets = Arc::new(VaultTargetSecretProvider::new(
        vault_transport,
        vault_profiles,
    )?);

    let proxy = Arc::new(ToolProxy::new(
        registry.clone(),
        authorization.clone(),
        credentials.clone(),
        secrets,
        connectors,
        Arc::new(DeferredProductionAuditSink),
    )?);
    let store = PostgresInvocationStore::new(pool);
    let execution_owner = canonical_uuid(&required_env("AGENT_TRUST_TOOL_PROXY_INSTANCE_ID")?)?;
    let service = Arc::new(ProductionToolProxyService::new(
        proxy,
        store,
        execution_owner,
    )?);
    let identities = parse_identities(&required_env("AGENT_TRUST_TOOL_PROXY_CLIENT_IDENTITIES")?)?;
    let authorizer = Arc::new(TokenBindingToolProxyAuthorizer::from_file(
        &required_file("AGENT_TRUST_TOOL_PROXY_TOKEN_BINDINGS_FILE", true)?,
        &identities,
    )?);
    service
        .store()
        .recover_expired_executing(authorizer.tenants())
        .await?;
    if !service.store().ready(authorizer.tenants()).await
        || !registry.ready(authorizer.tenants()).await
        || !credentials.ready().await
        || !authorization.ready()
    {
        return Err("TOOL_PROXY_NOT_READY".into());
    }
    serve(
        ToolProxyServerConfig {
            data_address: arguments.data,
            management_address: arguments.management,
            tls_ca_file: required_file("AGENT_TRUST_TOOL_PROXY_TLS_CA_FILE", false)?,
            tls_certificate_file: required_file(
                "AGENT_TRUST_TOOL_PROXY_TLS_CERTIFICATE_FILE",
                false,
            )?,
            tls_private_key_file: required_file(
                "AGENT_TRUST_TOOL_PROXY_TLS_PRIVATE_KEY_FILE",
                true,
            )?,
            client_identities: identities,
        },
        ToolProxyServerDependencies {
            service,
            registry,
            credentials,
            authorization,
            authorizer,
        },
    )
    .await?;
    Ok(())
}

#[derive(Clone)]
struct ParsedVerificationKey {
    issuer: String,
    key_id: String,
    key_usages: BTreeSet<String>,
    key: VerifyingKey,
}

fn read_verification_keys(
    path: &Path,
) -> Result<Vec<ParsedVerificationKey>, Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)?;
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err("TOOL_PROXY_VERIFICATION_KEYS_INVALID".into());
    }
    let document: VerificationKeyDocument = serde_json::from_slice(&raw)?;
    if document.schema_version != VERIFICATION_KEYS_SCHEMA
        || document.keys.is_empty()
        || document.keys.len() > 128
    {
        return Err("TOOL_PROXY_VERIFICATION_KEYS_INVALID".into());
    }
    let allowed = BTreeSet::from([
        "PEP_EXECUTION_AUTHORIZATION",
        "WORKLOAD_CREDENTIAL_BINDING",
        "WORKLOAD_CREDENTIAL_CONSUMPTION",
        "REGISTRY_SNAPSHOT",
        TARGET_PROFILE_KEY_USAGE,
    ]);
    let mut unique = BTreeSet::new();
    let mut result = Vec::new();
    for entry in document.keys {
        let key_usages = entry.key_usages.iter().cloned().collect::<BTreeSet<_>>();
        if !valid_identifier(&entry.issuer)
            || !valid_identifier(&entry.key_id)
            || key_usages.is_empty()
            || key_usages.len() != entry.key_usages.len()
            || !key_usages
                .iter()
                .all(|usage| allowed.contains(usage.as_str()))
            || !unique.insert(entry.key_id.clone())
            || entry.public_key_base64url.contains('=')
        {
            return Err("TOOL_PROXY_VERIFICATION_KEYS_INVALID".into());
        }
        let raw = URL_SAFE_NO_PAD.decode(&entry.public_key_base64url)?;
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "TOOL_PROXY_VERIFICATION_KEYS_INVALID")?;
        result.push(ParsedVerificationKey {
            issuer: entry.issuer,
            key_id: entry.key_id,
            key_usages,
            key: VerifyingKey::from_bytes(&bytes)?,
        });
    }
    Ok(result)
}

fn read_and_verify_profiles(
    path: &Path,
    keys: &[ParsedVerificationKey],
) -> Result<SignedTargetProfiles, Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)?;
    if raw.is_empty() || raw.len() > 1_048_576 {
        return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
    }
    let document: SignedTargetProfiles = serde_json::from_slice(&raw)?;
    if document.schema_version != TARGET_PROFILES_SCHEMA
        || document.key_usage != TARGET_PROFILE_KEY_USAGE
        || document.profiles.is_empty()
        || document.profiles.len() > 1_000
        || document.signature.contains('=')
    {
        return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
    }
    let key = keys
        .iter()
        .find(|key| {
            key.issuer == document.issuer
                && key.key_id == document.key_id
                && key.key_usages.contains(TARGET_PROFILE_KEY_USAGE)
        })
        .ok_or("TOOL_PROXY_TARGET_PROFILES_INVALID")?;
    let mut material = document.clone();
    material.signature.clear();
    let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&material)?));
    let raw_signature = URL_SAFE_NO_PAD.decode(&document.signature)?;
    key.key
        .verify(digest.as_bytes(), &Signature::from_slice(&raw_signature)?)?;
    Ok(document)
}

fn build_profiles(
    profiles: Vec<TargetProfile>,
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
) -> Result<
    (
        Vec<VaultLeaseProfile>,
        Vec<Arc<dyn agent_trust_tool_proxy::Connector>>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut vault_profiles = Vec::new();
    let mut connector_profiles: BTreeMap<String, BTreeMap<PoolIsolationKey, HttpTargetProfile>> =
        BTreeMap::new();
    let mut connector_resolutions: BTreeMap<
        String,
        BTreeMap<PoolIsolationKey, (String, Vec<SocketAddr>)>,
    > = BTreeMap::new();
    let mut globally_unique_targets = BTreeSet::new();
    for profile in profiles {
        let tenant = canonical_tenant(&profile.tenant_id)?;
        if !valid_identifier(&profile.target_profile)
            || !valid_identifier(&profile.credential_profile)
            || !valid_identifier(&profile.executor_profile)
            || profile.lease_path.is_empty()
            || profile.lease_path.len() > 256
            || profile.lease_path.starts_with('/')
            || profile
                .lease_path
                .split('/')
                .any(|part| part.is_empty() || part == "..")
            || !valid_identifier(&profile.secret_field)
            || profile.operations.is_empty()
        {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        let isolation = PoolIsolationKey {
            tenant_id: tenant.clone(),
            credential_profile: profile.credential_profile.clone(),
            target_profile: profile.target_profile.clone(),
        };
        if !globally_unique_targets.insert(isolation.clone()) {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        let base_url = strict_https_root(&profile.base_url)?;
        let host = base_url
            .host_str()
            .ok_or("TOOL_PROXY_TARGET_PROFILES_INVALID")?
            .to_string();
        let port = base_url
            .port_or_known_default()
            .ok_or("TOOL_PROXY_TARGET_PROFILES_INVALID")?;
        let internal_route = internal_control_plane_route(
            &profile.executor_profile,
            &profile.target_profile,
            &profile.credential_profile,
            &host,
            port,
        );
        if profile.pinned_addresses.is_empty() || profile.pinned_addresses.len() > 8 {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        let mut pinned = Vec::new();
        let mut unique_pinned = BTreeSet::new();
        for address in profile.pinned_addresses {
            let ip: IpAddr = address.parse()?;
            if !(is_public_target_ip(ip)
                || internal_route.is_some() && is_private_control_plane_ip(ip))
                || !unique_pinned.insert(ip)
            {
                return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
            }
            pinned.push(SocketAddr::new(ip, port));
        }
        if let Ok(literal_host) = host.parse::<IpAddr>()
            && (unique_pinned.len() != 1 || !unique_pinned.contains(&literal_host))
        {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        if connector_resolutions
            .entry(profile.executor_profile.clone())
            .or_default()
            .insert(isolation.clone(), (host, pinned))
            .is_some()
        {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        let mut operations = BTreeMap::new();
        for (operation_id, operation) in profile.operations {
            if !valid_identifier(&operation_id)
                || !operation.path.starts_with('/')
                || operation.path.contains("..")
                || operation.path.contains('%')
                || operation.path.contains('\\')
                || operation.path.contains('?')
                || operation.path.contains('#')
                || operation.content_type != "application/json"
                || !matches!(
                    operation.method.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
                )
                || internal_route.is_some_and(|route| {
                    operation.method != "POST" || operation.path != route
                })
                || operations
                    .insert(
                        operation_id,
                        HttpOperation {
                            method: reqwest::Method::from_bytes(operation.method.as_bytes())?,
                            path: operation.path,
                            content_type: operation.content_type,
                        },
                    )
                    .is_some()
            {
                return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
            }
        }
        if connector_profiles
            .entry(profile.executor_profile.clone())
            .or_default()
            .insert(
                isolation,
                HttpTargetProfile {
                    base_url,
                    operations,
                },
            )
            .is_some()
        {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        vault_profiles.push(VaultLeaseProfile {
            tenant_id: tenant,
            credential_profile: profile.credential_profile,
            target: profile.target_profile,
            lease_path: profile.lease_path,
            secret_field: profile.secret_field,
        });
    }
    let mut connectors: Vec<Arc<dyn agent_trust_tool_proxy::Connector>> = Vec::new();
    for (executor_profile, targets) in connector_profiles {
        let resolutions = connector_resolutions
            .remove(&executor_profile)
            .ok_or("TOOL_PROXY_TARGET_PROFILES_INVALID")?;
        if targets.keys().ne(resolutions.keys()) {
            return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
        }
        let mut clients = BTreeMap::new();
        for (isolation, (host, addresses)) in resolutions {
            let target_resolution = BTreeMap::from([(host, addresses)]);
            if clients
                .insert(
                    isolation,
                    build_mtls_client(
                        ca_file,
                        certificate_file,
                        private_key_file,
                        Duration::from_secs(30),
                        &target_resolution,
                    )?,
                )
                .is_some()
            {
                return Err("TOOL_PROXY_TARGET_PROFILES_INVALID".into());
            }
        }
        connectors.push(Arc::new(HttpConnector::new_production(
            executor_profile,
            targets,
            clients,
        )?));
    }
    Ok((vault_profiles, connectors))
}

fn build_mtls_client(
    ca_file: &Path,
    certificate_file: &Path,
    private_key_file: &Path,
    timeout: Duration,
    resolutions: &BTreeMap<String, Vec<SocketAddr>>,
) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let ca = std::fs::read(ca_file)?;
    let certificate = std::fs::read(certificate_file)?;
    let mut private_key = Zeroizing::new(std::fs::read(private_key_file)?);
    let mut identity_pem =
        Zeroizing::new(Vec::with_capacity(certificate.len() + private_key.len()));
    identity_pem.extend_from_slice(&certificate);
    identity_pem.extend_from_slice(&private_key);
    private_key.zeroize();
    let mut builder = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .identity(reqwest::Identity::from_pem(&identity_pem)?)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(timeout);
    for (host, addresses) in resolutions {
        builder = builder.resolve_to_addrs(host, addresses);
    }
    Ok(builder.build()?)
}

fn validate_database_url(
    value: &str,
    ca_file: &Path,
    password: &str,
) -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
    let parsed = Url::parse(value)?;
    let mut normalized = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let normalized_key = key.to_ascii_lowercase();
        if key.as_ref() != normalized_key
            || value.is_empty()
            || normalized
                .insert(normalized_key, value.into_owned())
                .is_some()
        {
            return Err("TOOL_PROXY_DATABASE_URL_INVALID".into());
        }
    }
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path().trim_matches('/').is_empty()
        || parsed.path().trim_matches('/').contains('/')
        || parsed.fragment().is_some()
        || normalized.len() != 2
        || normalized.get("sslmode").map(String::as_str) != Some("verify-full")
        || normalized.get("options").map(String::as_str) != Some("-csearch_path=pg_catalog,public")
        || !ca_file.is_absolute()
        || password.is_empty()
        || password.len() > 65_536
    {
        return Err("TOOL_PROXY_DATABASE_URL_INVALID".into());
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
         rolreplication,rolinherit,current_setting('search_path') AS search_path,\
         current_schemas(false)::text AS resolved_schemas,current_setting('row_security') AS row_security,\
         has_schema_privilege(current_user,'public','CREATE') AS can_create,\
         has_schema_privilege(current_user,'public','USAGE') AS can_use_schema,\
         has_database_privilege(current_user,current_database(),'TEMP') AS can_temp,\
         (has_table_privilege(current_user,'public.tool_proxy_invocations','SELECT') AND\
          has_table_privilege(current_user,'public.tool_proxy_invocations','INSERT') AND\
          has_table_privilege(current_user,'public.tool_proxy_invocations','UPDATE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_invocations','DELETE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_invocations','TRUNCATE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_invocations','REFERENCES') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_invocations','TRIGGER')) AS invocation_grants_ok,\
         (has_table_privilege(current_user,'public.tool_proxy_audit_events','INSERT') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_audit_events','SELECT') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_audit_events','UPDATE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_audit_events','DELETE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_audit_events','TRUNCATE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_audit_events','REFERENCES') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_audit_events','TRIGGER')) AS audit_grants_ok,\
         (has_table_privilege(current_user,'public.tool_proxy_outbox','INSERT') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_outbox','SELECT') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_outbox','UPDATE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_outbox','DELETE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_outbox','TRUNCATE') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_outbox','REFERENCES') AND NOT\
          has_table_privilege(current_user,'public.tool_proxy_outbox','TRIGGER')) AS outbox_grants_ok \
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
        || row.try_get::<bool, _>("can_create")?
        || row.try_get::<bool, _>("can_temp")?
        || !row.try_get::<bool, _>("can_use_schema")?
        || !row.try_get::<bool, _>("invocation_grants_ok")?
        || !row.try_get::<bool, _>("audit_grants_ok")?
        || !row.try_get::<bool, _>("outbox_grants_ok")?
        || row.try_get::<String, _>("search_path")? != "pg_catalog, public"
        || row.try_get::<String, _>("resolved_schemas")? != "{pg_catalog,public}"
        || row.try_get::<String, _>("row_security")? != "on"
    {
        return Err("TOOL_PROXY_DATABASE_ROLE_UNSAFE".into());
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
        let value = arguments.next().ok_or("TOOL_PROXY_ARGUMENTS_INVALID")?;
        match argument.as_str() {
            "--listen" => listen = value,
            "--port" => port = value.parse()?,
            "--management-listen" => management_listen = value,
            "--management-port" => management_port = value.parse()?,
            _ => return Err("TOOL_PROXY_ARGUMENTS_INVALID".into()),
        }
    }
    let data_ip: IpAddr = listen.parse()?;
    let management_ip: IpAddr = management_listen.parse()?;
    if port == 0
        || management_port == 0
        || port == management_port
        || !(management_ip.is_loopback() || management_ip.is_unspecified())
    {
        return Err("TOOL_PROXY_ARGUMENTS_INVALID".into());
    }
    Ok(Arguments {
        data: SocketAddr::new(data_ip, port),
        management: SocketAddr::new(management_ip, management_port),
    })
}

fn is_private_control_plane_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => {
            value.is_private()
                && !value.is_loopback()
                && !value.is_link_local()
                && !value.is_broadcast()
                && !value.is_unspecified()
        }
        IpAddr::V6(value) => {
            value.is_unique_local()
                && !value.is_loopback()
                && !value.is_unicast_link_local()
                && !value.is_multicast()
                && !value.is_unspecified()
        }
    }
}

fn internal_control_plane_route(
    executor_profile: &str,
    target_profile: &str,
    credential_profile: &str,
    host: &str,
    port: u16,
) -> Option<&'static str> {
    if port != 443 {
        return None;
    }
    let (service, route) = match (
        executor_profile,
        target_profile,
        credential_profile,
    ) {
        (
            "enterprise-control-executor",
            "enterprise-control-authority",
            "enterprise-executor",
        ) => ("agenttrust-enterprise-authority", "/v1/enterprise/mutations"),
        (
            "policy-administration-executor",
            "policy-administration-authority",
            "policy-administration-executor",
        ) => ("agenttrust-policy-admin", "/v1/policies/executions"),
        (
            "incident-release-executor",
            "incident-release-authority",
            "incident-release-executor",
        ) => ("agenttrust-incident-release", "/v1/incidents/executions"),
        (
            "pack-marketplace-executor",
            "pack-marketplace-authority",
            "pack-marketplace-executor",
        ) => ("agenttrust-pack-marketplace", "/v1/packs/executions"),
        _ => return None,
    };
    service_host_matches(host, service).then_some(route)
}

fn service_host_matches(host: &str, service: &str) -> bool {
    if host == service {
        return true;
    }
    let Some(prefix) = host.strip_suffix(".svc.cluster.local") else {
        return false;
    };
    let Some((actual_service, namespace)) = prefix.split_once('.') else {
        return false;
    };
    actual_service == service
        && !namespace.is_empty()
        && !namespace.contains('.')
        && namespace.len() <= 63
        && namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !namespace.starts_with('-')
        && !namespace.ends_with('-')
}

fn strict_https_root(value: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let url = Url::parse(value)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("TOOL_PROXY_HTTPS_ENDPOINT_INVALID".into());
    }
    Ok(url)
}

fn canonical_tenant(value: &str) -> Result<TenantId, Box<dyn std::error::Error>> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| id.to_string() == value)
        .map(|id| TenantId(id.to_string()))
        .ok_or_else(|| "TOOL_PROXY_TENANT_INVALID".into())
}

fn canonical_uuid(value: &str) -> Result<String, Box<dyn std::error::Error>> {
    Uuid::parse_str(value)
        .ok()
        .filter(|id| id.to_string() == value)
        .map(|id| id.to_string())
        .ok_or_else(|| "TOOL_PROXY_INSTANCE_ID_INVALID".into())
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name}_REQUIRED").into())
}

fn required_identifier(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let value = required_env(name)?;
    if !valid_identifier(&value) {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:@/-".contains(&byte))
}

fn read_secret(name: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    if std::fs::metadata(&path)?.len() > 65_536 {
        return Err(format!("{name}_INVALID").into());
    }
    let value = Zeroizing::new(std::fs::read_to_string(path)?);
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value)
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
        .collect::<Vec<_>>();
    let unique = values.iter().cloned().collect::<BTreeSet<_>>();
    if values.is_empty()
        || values.len() > 4_096
        || unique.len() != values.len()
        || values.iter().any(|value| {
            value.is_empty()
                || value.len() > 512
                || !(value.starts_with("DNS:") || value.starts_with("URI:"))
        })
    {
        return Err("TOOL_PROXY_CLIENT_IDENTITIES_INVALID".into());
    }
    Ok(unique)
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let access = if private {
        private_file_access_allowed(mode, metadata.uid(), metadata.gid(), uid, gid)
    } else {
        mode & 0o022 == 0
    };
    Ok(metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() > 0
        && metadata.len() <= 1_048_576
        && access)
}

#[cfg(unix)]
fn private_file_access_allowed(
    mode: u32,
    file_uid: u32,
    file_gid: u32,
    effective_uid: u32,
    effective_gid: u32,
) -> bool {
    let allowed_bits = 0o400 | if file_gid == effective_gid { 0o040 } else { 0 };
    let actually_readable = (file_uid == effective_uid && mode & 0o400 != 0)
        || (file_gid == effective_gid && mode & 0o040 != 0);
    actually_readable && mode & !allowed_bits == 0
}

#[cfg(not(unix))]
fn secure_file(_path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listeners_and_database_urls_fail_closed() {
        let defaults = parse_args(Vec::new()).unwrap_or_else(|error| panic!("args: {error}"));
        assert_eq!(defaults.data.port(), 8086);
        assert_eq!(defaults.management.port(), 9096);
        assert!(parse_args(["--management-port".into(), "8086".into()]).is_err());
        let ca = Path::new("/var/run/agenttrust/db-ca.pem");
        let valid = "postgresql://tool_proxy@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic";
        assert!(validate_database_url(valid, ca, "separate-secret").is_ok());
        assert!(validate_database_url(
            "postgresql://tool_proxy:embedded@db.prod/agenttrust?sslmode=verify-full&options=-csearch_path%3Dpg_catalog%2Cpublic",
            ca,
            "separate-secret",
        ).is_err());
    }

    #[test]
    fn only_service_network_addresses_are_private_control_plane_targets() {
        assert!(is_private_control_plane_ip(IpAddr::from([10, 40, 2, 17])));
        assert!(is_private_control_plane_ip(IpAddr::V6(
            std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x17,)
        )));
        assert!(!is_private_control_plane_ip(IpAddr::from([127, 0, 0, 1])));
        assert!(!is_private_control_plane_ip(IpAddr::from([
            169, 254, 169, 254
        ])));
        assert!(!is_private_control_plane_ip(IpAddr::from([8, 8, 8, 8])));
    }

    #[test]
    fn private_authority_profiles_have_exact_identity_host_port_and_route() {
        assert_eq!(
            internal_control_plane_route(
                "policy-administration-executor",
                "policy-administration-authority",
                "policy-administration-executor",
                "agenttrust-policy-admin",
                443,
            ),
            Some("/v1/policies/executions")
        );
        assert_eq!(
            internal_control_plane_route(
                "incident-release-executor",
                "incident-release-authority",
                "incident-release-executor",
                "agenttrust-incident-release.agenttrust.svc.cluster.local",
                443,
            ),
            Some("/v1/incidents/executions")
        );
        assert_eq!(
            internal_control_plane_route(
                "pack-marketplace-executor",
                "pack-marketplace-authority",
                "pack-marketplace-executor",
                "attacker-agenttrust-pack-marketplace.svc.cluster.local",
                443,
            ),
            None
        );
        assert_eq!(
            internal_control_plane_route(
                "pack-marketplace-executor",
                "pack-marketplace-authority",
                "wrong-credential",
                "agenttrust-pack-marketplace",
                443,
            ),
            None
        );
        assert_eq!(
            internal_control_plane_route(
                "pack-marketplace-executor",
                "pack-marketplace-authority",
                "pack-marketplace-executor",
                "agenttrust-pack-marketplace",
                8443,
            ),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_files_require_actual_owner_or_same_group_readability() {
        assert!(private_file_access_allowed(0o400, 1000, 2000, 1000, 3000));
        assert!(private_file_access_allowed(0o440, 1000, 3000, 1000, 3000));
        assert!(!private_file_access_allowed(0o440, 1000, 2000, 1000, 3000));
        assert!(!private_file_access_allowed(0o600, 1000, 2000, 1000, 3000));
        assert!(!private_file_access_allowed(0o444, 1000, 3000, 1000, 3000));
    }
}
