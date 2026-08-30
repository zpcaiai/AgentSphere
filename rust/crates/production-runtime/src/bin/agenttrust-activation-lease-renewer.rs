use agent_trust_action_ir::{ParseLimits, parse_strict_json};
use agent_trust_bounded_http::read_bounded_body;
use agent_trust_production_runtime::activation::{ActivationGuardian, ActivationGuardianConfig};
use agent_trust_production_runtime::database::{
    validated_connect_options, verify_database_posture,
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use url::Url;

const WATCH_MAX_BYTES: usize = 16 * 1024;
const WATCH_MAX_AGE_SECONDS: i64 = 30;
const RENEW_INTERVAL_SECONDS: u64 = 10;
const LEASE_SECONDS: i64 = 45;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationWatchStatus {
    schema_version: String,
    ready: bool,
    last_success_at: Option<DateTime<Utc>>,
    receipt_digest: Option<String>,
    revocation_registry_id: Option<String>,
    revocation_registry_sequence: Option<i64>,
    revocation_registry_digest: Option<String>,
    projection_id: Option<String>,
    projection_head_digest: Option<String>,
    maximum_age_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseRenewerStatus {
    schema_version: String,
    ready: bool,
    database_write_enabled: bool,
    release_id: String,
    lease_state: Option<String>,
    lease_revision: Option<i64>,
    lease_state_digest: Option<String>,
    revocation_registry_sequence: Option<i64>,
    projection_id: Option<String>,
    projection_head_digest: Option<String>,
    last_verified_at: Option<DateTime<Utc>>,
    last_renewed_at: Option<DateTime<Utc>>,
    valid_until: Option<DateTime<Utc>>,
    error_code: Option<String>,
}

impl LeaseRenewerStatus {
    fn initial(release_id: String) -> Self {
        Self {
            schema_version: "agenttrust.production-activation-lease-renewer-status.v1".to_string(),
            ready: false,
            database_write_enabled: false,
            release_id,
            lease_state: None,
            lease_revision: None,
            lease_state_digest: None,
            revocation_registry_sequence: None,
            projection_id: None,
            projection_head_digest: None,
            last_verified_at: None,
            last_renewed_at: None,
            valid_until: None,
            error_code: Some("ACTIVATION_LEASE_NOT_CHECKED".to_string()),
        }
    }
}

struct Configuration {
    release_id: String,
    watcher_url: Url,
    listen: SocketAddr,
    guardian: ActivationGuardian,
    database_url: String,
    database_password: String,
    database_ca: PathBuf,
    database_role: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    if let Some(command) = arguments.next() {
        if command != "check-active" {
            return Err("ACTIVATION_LEASE_ARGUMENTS_INVALID".into());
        }
        let url = arguments
            .next()
            .ok_or("ACTIVATION_LEASE_PROBE_URL_REQUIRED")?;
        let release_id = arguments
            .next()
            .ok_or("ACTIVATION_LEASE_PROBE_RELEASE_REQUIRED")?;
        let registry_sequence = arguments
            .next()
            .ok_or("ACTIVATION_LEASE_PROBE_REGISTRY_SEQUENCE_REQUIRED")?
            .parse()?;
        let projection_id = arguments
            .next()
            .ok_or("ACTIVATION_LEASE_PROBE_PROJECTION_REQUIRED")?;
        let projection_head_digest = arguments
            .next()
            .ok_or("ACTIVATION_LEASE_PROBE_PROJECTION_HEAD_REQUIRED")?;
        if arguments.next().is_some() {
            return Err("ACTIVATION_LEASE_ARGUMENTS_INVALID".into());
        }
        check_active_status(
            &url,
            &release_id,
            registry_sequence,
            &projection_id,
            &projection_head_digest,
        )
        .await?;
        return Ok(());
    }
    let config = Arc::new(load_configuration()?);
    let connect = validated_connect_options(
        &config.database_url,
        &config.database_password,
        &config.database_ca,
        &config.database_role,
    )?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .min_connections(1)
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect)
        .await?;
    verify_database_posture(&pool, &config.database_role).await?;

    let status = Arc::new(RwLock::new(LeaseRenewerStatus::initial(
        config.release_id.clone(),
    )));
    let updater_status = Arc::clone(&status);
    let updater_config = Arc::clone(&config);
    let updater_pool = pool.clone();
    let updater_client = reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()?;
    let updater = tokio::spawn(async move {
        loop {
            let next = match tokio::time::timeout(
                Duration::from_secs(5),
                renew_once(&updater_config, &updater_pool, &updater_client),
            )
            .await
            {
                Ok(value) => value,
                Err(_) => LeaseRenewerStatus {
                    error_code: Some("ACTIVATION_LEASE_RENEWAL_TIMEOUT".to_string()),
                    ..LeaseRenewerStatus::initial(updater_config.release_id.clone())
                },
            };
            *updater_status.write().await = next;
            tokio::time::sleep(Duration::from_secs(RENEW_INTERVAL_SECONDS)).await;
        }
    });

    let app = Router::new()
        .route("/ready", get(readiness))
        .route("/active", get(active))
        .with_state(status);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    let server = axum::serve(listener, app.into_make_service());
    tokio::select! {
        result = server => result?,
        result = updater => return Err(format!("ACTIVATION_LEASE_RENEWER_STOPPED:{result:?}").into()),
    }
    Ok(())
}

async fn readiness(
    State(status): State<Arc<RwLock<LeaseRenewerStatus>>>,
) -> (StatusCode, Json<LeaseRenewerStatus>) {
    let value = fresh_status(status.read().await.clone());
    let code = if value.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(value))
}

async fn active(
    State(status): State<Arc<RwLock<LeaseRenewerStatus>>>,
) -> (StatusCode, Json<LeaseRenewerStatus>) {
    let value = fresh_status(status.read().await.clone());
    let code = if value.ready && value.database_write_enabled {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(value))
}

fn fresh_status(mut value: LeaseRenewerStatus) -> LeaseRenewerStatus {
    let now = Utc::now();
    let watcher_fresh = value.last_verified_at.as_ref().is_some_and(|verified_at| {
        let age = now.signed_duration_since(*verified_at);
        age >= ChronoDuration::zero() && age <= ChronoDuration::seconds(WATCH_MAX_AGE_SECONDS)
    });
    let renewal_fresh = !value.database_write_enabled
        || (value.last_renewed_at.as_ref().is_some_and(|renewed_at| {
            let age = now.signed_duration_since(*renewed_at);
            age >= ChronoDuration::zero()
                && age <= ChronoDuration::seconds(RENEW_INTERVAL_SECONDS as i64 * 2)
        }) && value
            .valid_until
            .as_ref()
            .is_some_and(|valid_until| *valid_until > now));
    if !watcher_fresh || !renewal_fresh {
        value.ready = false;
        value.database_write_enabled = false;
        value.error_code = Some("ACTIVATION_LEASE_STATUS_STALE".to_string());
    }
    value
}

async fn renew_once(
    config: &Configuration,
    pool: &sqlx::PgPool,
    client: &reqwest::Client,
) -> LeaseRenewerStatus {
    match renew_once_inner(config, pool, client).await {
        Ok(status) => status,
        Err(code) => LeaseRenewerStatus {
            error_code: Some(code.to_string()),
            ..LeaseRenewerStatus::initial(config.release_id.clone())
        },
    }
}

async fn renew_once_inner(
    config: &Configuration,
    pool: &sqlx::PgPool,
    client: &reqwest::Client,
) -> Result<LeaseRenewerStatus, &'static str> {
    let now = Utc::now();
    let receipt = config
        .guardian
        .require_active()
        .map_err(|_| "ACTIVATION_LEASE_RECEIPT_INVALID")?;
    let watcher = read_watcher_status(client, &config.watcher_url, now).await?;
    if watcher.receipt_digest.as_deref() != Some(receipt.receipt_digest.as_str())
        || watcher.revocation_registry_id.as_deref()
            != Some(receipt.revocation_registry_id.as_str())
        || watcher
            .revocation_registry_sequence
            .map(|value| value as u64)
            != Some(receipt.revocation_sequence)
        || watcher.revocation_registry_digest.as_deref()
            != Some(receipt.revocation_registry_digest.as_str())
    {
        return Err("ACTIVATION_LEASE_WATCHER_RECEIPT_MISMATCH");
    }
    let verified_at = watcher
        .last_success_at
        .ok_or("ACTIVATION_LEASE_WATCHER_INVALID")?;
    let projection_id = watcher
        .projection_id
        .ok_or("ACTIVATION_LEASE_WATCHER_INVALID")?;
    let projection_head_digest = watcher
        .projection_head_digest
        .ok_or("ACTIVATION_LEASE_WATCHER_INVALID")?;
    let row = sqlx::query(
        "SELECT revision,state,release_id,certificate_id,state_digest::text AS state_digest, \
                CASE WHEN isfinite(valid_until) THEN valid_until ELSE NULL END AS valid_until \
         FROM public.production_activation_lease WHERE singleton",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| "ACTIVATION_LEASE_DATABASE_UNAVAILABLE")?;
    let revision = row
        .try_get::<i64, _>("revision")
        .map_err(|_| "ACTIVATION_LEASE_DATABASE_INVALID")?;
    let state = row
        .try_get::<String, _>("state")
        .map_err(|_| "ACTIVATION_LEASE_DATABASE_INVALID")?;
    let lease_release_id = row
        .try_get::<String, _>("release_id")
        .map_err(|_| "ACTIVATION_LEASE_DATABASE_INVALID")?;
    let certificate_id = row
        .try_get::<Option<String>, _>("certificate_id")
        .map_err(|_| "ACTIVATION_LEASE_DATABASE_INVALID")?;
    let state_digest = row
        .try_get::<String, _>("state_digest")
        .map_err(|_| "ACTIVATION_LEASE_DATABASE_INVALID")?;
    let current_valid_until = row
        .try_get::<Option<DateTime<Utc>>, _>("valid_until")
        .map_err(|_| "ACTIVATION_LEASE_DATABASE_INVALID")?;

    if state == "FENCED" {
        return Ok(LeaseRenewerStatus {
            schema_version: "agenttrust.production-activation-lease-renewer-status.v1".to_string(),
            ready: true,
            database_write_enabled: false,
            release_id: config.release_id.clone(),
            lease_state: Some(state),
            lease_revision: Some(revision),
            lease_state_digest: Some(state_digest),
            revocation_registry_sequence: watcher.revocation_registry_sequence,
            projection_id: Some(projection_id),
            projection_head_digest: Some(projection_head_digest),
            last_verified_at: Some(verified_at),
            last_renewed_at: None,
            valid_until: current_valid_until,
            error_code: None,
        });
    }
    if state != "ACTIVE"
        || lease_release_id != config.release_id
        || certificate_id.as_deref() != Some(receipt.certificate_id.as_str())
    {
        return Err("ACTIVATION_LEASE_RELEASE_NOT_ACTIVE");
    }
    let requested_valid_until = now + ChronoDuration::seconds(LEASE_SECONDS);
    let renewed = sqlx::query(
        "SELECT renewed_revision,renewed_state_digest::text AS renewed_state_digest,renewed_valid_until \
         FROM public.agenttrust_renew_production_activation( \
           $1::char(64),$2::text,$3::text,$4::text,$5::bigint,$6::char(64), \
           $7::text,$8::char(64),$9::timestamptz,$10::timestamptz \
         )",
    )
    .bind(&state_digest)
    .bind(&config.release_id)
    .bind(&receipt.certificate_id)
    .bind(&receipt.revocation_registry_id)
    .bind(receipt.revocation_sequence as i64)
    .bind(&receipt.revocation_registry_digest)
    .bind(&projection_id)
    .bind(&projection_head_digest)
    .bind(verified_at)
    .bind(requested_valid_until)
    .fetch_one(pool)
    .await
    .map_err(|_| "ACTIVATION_LEASE_RENEWAL_REJECTED")?;
    let renewed_at = Utc::now();
    let valid_until = renewed
        .try_get::<DateTime<Utc>, _>("renewed_valid_until")
        .map_err(|_| "ACTIVATION_LEASE_RENEWAL_RESPONSE_INVALID")?;
    if valid_until <= renewed_at
        || valid_until > renewed_at + ChronoDuration::seconds(LEASE_SECONDS)
    {
        return Err("ACTIVATION_LEASE_RENEWAL_RESPONSE_INVALID");
    }
    Ok(LeaseRenewerStatus {
        schema_version: "agenttrust.production-activation-lease-renewer-status.v1".to_string(),
        ready: true,
        database_write_enabled: true,
        release_id: config.release_id.clone(),
        lease_state: Some("ACTIVE".to_string()),
        lease_revision: Some(
            renewed
                .try_get::<i64, _>("renewed_revision")
                .map_err(|_| "ACTIVATION_LEASE_RENEWAL_RESPONSE_INVALID")?,
        ),
        lease_state_digest: Some(
            renewed
                .try_get::<String, _>("renewed_state_digest")
                .map_err(|_| "ACTIVATION_LEASE_RENEWAL_RESPONSE_INVALID")?,
        ),
        revocation_registry_sequence: watcher.revocation_registry_sequence,
        projection_id: Some(projection_id),
        projection_head_digest: Some(projection_head_digest),
        last_verified_at: Some(verified_at),
        last_renewed_at: Some(renewed_at),
        valid_until: Some(valid_until),
        error_code: None,
    })
}

async fn check_active_status(
    raw_url: &str,
    expected_release_id: &str,
    expected_registry_sequence: i64,
    expected_projection_id: &str,
    expected_projection_head_digest: &str,
) -> Result<(), &'static str> {
    let url = Url::parse(raw_url).map_err(|_| "ACTIVATION_LEASE_PROBE_URL_INVALID")?;
    let host = url
        .host_str()
        .and_then(|value| value.parse::<IpAddr>().ok());
    if url.scheme() != "http"
        || host.is_none_or(|value| !value.is_loopback())
        || url.port_or_known_default().is_none_or(|port| port == 0)
        || url.path() != "/active"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || !is_release_id(expected_release_id)
        || expected_registry_sequence <= 0
        || expected_projection_id.is_empty()
        || expected_projection_id.len() > 256
        || !is_identifier(expected_projection_id)
        || !is_digest(expected_projection_head_digest)
    {
        return Err("ACTIVATION_LEASE_PROBE_INPUT_INVALID");
    }
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| "ACTIVATION_LEASE_PROBE_CLIENT_INVALID")?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "ACTIVATION_LEASE_PROBE_UNAVAILABLE")?;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
        || response
            .content_length()
            .is_some_and(|value| value as usize > WATCH_MAX_BYTES)
    {
        return Err("ACTIVATION_LEASE_PROBE_NOT_ACTIVE");
    }
    let bytes = read_bounded_body(response, WATCH_MAX_BYTES)
        .await
        .map_err(|_| "ACTIVATION_LEASE_PROBE_RESPONSE_INVALID")?;
    let value = parse_strict_json(
        &bytes,
        &ParseLimits {
            max_body_bytes: WATCH_MAX_BYTES,
            max_depth: 6,
            max_array_items: 0,
            max_string_bytes: 1_024,
            max_object_keys: 32,
            max_number_chars: 32,
        },
    )
    .map_err(|_| "ACTIVATION_LEASE_PROBE_RESPONSE_INVALID")?;
    let status: LeaseRenewerStatus =
        serde_json::from_value(value).map_err(|_| "ACTIVATION_LEASE_PROBE_RESPONSE_INVALID")?;
    let status = fresh_status(status);
    if status.schema_version != "agenttrust.production-activation-lease-renewer-status.v1"
        || !status.ready
        || !status.database_write_enabled
        || status.release_id != expected_release_id
        || status.lease_state.as_deref() != Some("ACTIVE")
        || status.revocation_registry_sequence != Some(expected_registry_sequence)
        || status.projection_id.as_deref() != Some(expected_projection_id)
        || status.projection_head_digest.as_deref() != Some(expected_projection_head_digest)
        || status.error_code.is_some()
    {
        return Err("ACTIVATION_LEASE_PROBE_NOT_ACTIVE");
    }
    Ok(())
}

async fn read_watcher_status(
    client: &reqwest::Client,
    url: &Url,
    now: DateTime<Utc>,
) -> Result<ActivationWatchStatus, &'static str> {
    let response = client
        .get(url.clone())
        .send()
        .await
        .map_err(|_| "ACTIVATION_LEASE_WATCHER_UNAVAILABLE")?;
    if response.status() != StatusCode::OK
        || response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| !value.eq_ignore_ascii_case("application/json"))
        || response
            .content_length()
            .is_some_and(|value| value as usize > WATCH_MAX_BYTES)
    {
        return Err("ACTIVATION_LEASE_WATCHER_INVALID");
    }
    let bytes = read_bounded_body(response, WATCH_MAX_BYTES)
        .await
        .map_err(|_| "ACTIVATION_LEASE_WATCHER_INVALID")?;
    let value = parse_strict_json(
        &bytes,
        &ParseLimits {
            max_body_bytes: WATCH_MAX_BYTES,
            max_depth: 6,
            max_array_items: 0,
            max_string_bytes: 1_024,
            max_object_keys: 32,
            max_number_chars: 32,
        },
    )
    .map_err(|_| "ACTIVATION_LEASE_WATCHER_INVALID")?;
    let status: ActivationWatchStatus =
        serde_json::from_value(value).map_err(|_| "ACTIVATION_LEASE_WATCHER_INVALID")?;
    let verified_at = status
        .last_success_at
        .ok_or("ACTIVATION_LEASE_WATCHER_INVALID")?;
    let age = now.signed_duration_since(verified_at);
    if status.schema_version != "agenttrust.production-activation-watch-status.v1"
        || !status.ready
        || status.maximum_age_seconds != 60
        || age < ChronoDuration::zero()
        || age > ChronoDuration::seconds(WATCH_MAX_AGE_SECONDS)
        || status
            .receipt_digest
            .as_deref()
            .is_none_or(|value| !is_digest(value))
        || status
            .revocation_registry_id
            .as_deref()
            .is_none_or(|value| value.is_empty() || value.len() > 256 || !is_identifier(value))
        || status
            .revocation_registry_sequence
            .is_none_or(|value| value <= 0)
        || status
            .revocation_registry_digest
            .as_deref()
            .is_none_or(|value| !is_digest(value))
        || status
            .projection_id
            .as_deref()
            .is_none_or(|value| value.is_empty() || value.len() > 256 || !is_identifier(value))
        || status
            .projection_head_digest
            .as_deref()
            .is_none_or(|value| !is_digest(value))
    {
        return Err("ACTIVATION_LEASE_WATCHER_INVALID");
    }
    Ok(status)
}

fn load_configuration() -> Result<Configuration, Box<dyn std::error::Error>> {
    let release_id = required_env("AGENT_TRUST_ACTIVATION_LEASE_RELEASE_ID")?;
    let watcher_url = Url::parse(&required_env("AGENT_TRUST_ACTIVATION_LEASE_WATCHER_URL")?)?;
    let watcher_host = watcher_url
        .host_str()
        .and_then(|value| value.parse::<IpAddr>().ok());
    if watcher_url.scheme() != "http"
        || watcher_host.is_none_or(|value| !value.is_loopback())
        || watcher_url
            .port_or_known_default()
            .is_none_or(|port| port == 0)
        || watcher_url.path() != "/ready"
        || watcher_url.query().is_some()
        || watcher_url.fragment().is_some()
        || !watcher_url.username().is_empty()
        || watcher_url.password().is_some()
    {
        return Err("ACTIVATION_LEASE_WATCHER_URL_INVALID".into());
    }
    let listen: SocketAddr = required_env("AGENT_TRUST_ACTIVATION_LEASE_LISTEN")?.parse()?;
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err("ACTIVATION_LEASE_LISTEN_INVALID".into());
    }
    let owner_uid = required_env("AGENT_TRUST_ACTIVATION_LEASE_RECEIPT_OWNER_UID")?.parse()?;
    let reader_gid = required_env("AGENT_TRUST_ACTIVATION_LEASE_RECEIPT_READER_GID")?.parse()?;
    let receipt_path = PathBuf::from(required_env("AGENT_TRUST_ACTIVATION_LEASE_RECEIPT_FILE")?);
    let guardian = ActivationGuardian::new(ActivationGuardianConfig {
        release_id: release_id.clone(),
        receipt_path,
        max_staleness_seconds: WATCH_MAX_AGE_SECONDS as u64,
        receipt_owner_uid: owner_uid,
        receipt_reader_gid: reader_gid,
    })?;
    Ok(Configuration {
        release_id,
        watcher_url,
        listen,
        guardian,
        database_url: read_secret("AGENT_TRUST_ACTIVATION_LEASE_DATABASE_URL_FILE")?,
        database_password: read_secret("AGENT_TRUST_ACTIVATION_LEASE_DATABASE_PASSWORD_FILE")?,
        database_ca: required_file("AGENT_TRUST_ACTIVATION_LEASE_DATABASE_CA_FILE", false)?,
        database_role: required_env("AGENT_TRUST_ACTIVATION_LEASE_DATABASE_EXPECTED_ROLE")?,
    })
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name}_REQUIRED").into())
}

fn read_secret(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = required_file(name, true)?;
    if std::fs::metadata(&path)?.len() > 65_536 {
        return Err(format!("{name}_INVALID").into());
    }
    let value = std::fs::read_to_string(path)?;
    let value = value.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(value.to_string())
}

fn required_file(name: &str, private: bool) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute() || !secure_file(&path, private)? {
        return Err(format!("{name}_INVALID").into());
    }
    Ok(path)
}

#[cfg(unix)]
fn secure_file(path: &Path, private: bool) -> Result<bool, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let mode = metadata.permissions().mode() & 0o7777;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    let readable = (metadata.uid() == uid && mode & 0o400 != 0)
        || (metadata.gid() == gid && mode & 0o040 != 0);
    let access = if private {
        readable && mode & !0o440 == 0
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
fn secure_file(path: &Path, _private: bool) -> Result<bool, std::io::Error> {
    let metadata = std::fs::metadata(path)?;
    Ok(metadata.is_file() && metadata.len() > 0 && metadata.len() <= 1_048_576)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_release_id(value: &str) -> bool {
    value.strip_prefix("git:sha1:").is_some_and(|digest| {
        digest.len() == 40
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) || value.strip_prefix("git:sha256:").is_some_and(is_digest)
}

fn is_identifier(value: &str) -> bool {
    value.bytes().enumerate().all(|(index, byte)| {
        byte.is_ascii_alphanumeric()
            || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
    })
}
