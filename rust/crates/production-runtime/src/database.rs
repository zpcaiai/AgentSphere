//! Shared fail-closed PostgreSQL client posture for production binaries.

use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProductionDatabaseError {
    #[error("PRODUCTION_DATABASE_CONFIGURATION_INVALID")]
    ConfigurationInvalid,
    #[error("PRODUCTION_DATABASE_QUERY_FAILED")]
    QueryFailed,
    #[error("PRODUCTION_DATABASE_ROLE_UNSAFE")]
    RoleUnsafe,
}

pub fn validated_connect_options(
    value: &str,
    password: &str,
    ca_file: &Path,
    expected_role: &str,
) -> Result<PgConnectOptions, ProductionDatabaseError> {
    let parsed =
        url::Url::parse(value).map_err(|_| ProductionDatabaseError::ConfigurationInvalid)?;
    let query = parsed.query_pairs().collect::<Vec<_>>();
    let mut normalized = BTreeMap::new();
    for (key, value) in &query {
        let key = key.to_ascii_lowercase();
        if value.is_empty() || normalized.insert(key, value.as_ref()).is_some() {
            return Err(ProductionDatabaseError::ConfigurationInvalid);
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
        return Err(ProductionDatabaseError::ConfigurationInvalid);
    }
    PgConnectOptions::from_str(value)
        .map(|options| {
            options
                .password(password)
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert(ca_file)
        })
        .map_err(|_| ProductionDatabaseError::ConfigurationInvalid)
}

pub async fn verify_database_posture(
    pool: &sqlx::PgPool,
    expected_role: &str,
) -> Result<(), ProductionDatabaseError> {
    let row = sqlx::query(
        "SELECT current_user AS role_name,rolsuper,rolbypassrls,current_setting('search_path') AS search_path, \
         current_schemas(false)::text AS resolved_schemas FROM pg_roles WHERE rolname=current_user",
    )
    .fetch_one(pool)
    .await
    .map_err(|_| ProductionDatabaseError::QueryFailed)?;
    let role_name = row
        .try_get::<String, _>("role_name")
        .map_err(|_| ProductionDatabaseError::QueryFailed)?;
    let superuser = row
        .try_get::<bool, _>("rolsuper")
        .map_err(|_| ProductionDatabaseError::QueryFailed)?;
    let bypasses_rls = row
        .try_get::<bool, _>("rolbypassrls")
        .map_err(|_| ProductionDatabaseError::QueryFailed)?;
    let search_path = row
        .try_get::<String, _>("search_path")
        .map_err(|_| ProductionDatabaseError::QueryFailed)?;
    let resolved = row
        .try_get::<String, _>("resolved_schemas")
        .map_err(|_| ProductionDatabaseError::QueryFailed)?;
    if role_name != expected_role
        || superuser
        || bypasses_rls
        || search_path != "pg_catalog, public"
        || resolved != "{pg_catalog,public}"
    {
        return Err(ProductionDatabaseError::RoleUnsafe);
    }
    Ok(())
}
