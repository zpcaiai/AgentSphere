use agent_trust_pack_supply_chain::production::{PostgresSupplyChainStore, SupplyChainAuthority, SupplyReceiptKeyring};
use agent_trust_pack_supply_chain::server::{
    EvidenceEventKeyring, HttpSupplyChainRuntimePort, SupplyDependency, SupplyServerConfig, SupplyTokenAuthorizer,
    router, serve,
};
use reqwest::{Certificate, Identity};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use std::collections::BTreeSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("SUPPLY_CHAIN_AUTHORITY_STARTUP_FAILED");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    if nix::unistd::Uid::effective().is_root() {
        return Err("SUPPLY_CHAIN_ROOT_PROCESS_DENIED".into());
    }
    let database_url=read_secret_file("AGENT_TRUST_SUPPLY_DATABASE_URL_FILE",16,16_384)?;
    let mut database_password=read_secret_file("AGENT_TRUST_SUPPLY_DATABASE_PASSWORD_FILE",16,8192)?;
    let expected_role=required_identifier("AGENT_TRUST_SUPPLY_DATABASE_EXPECTED_ROLE")?;
    let database_ca=required_path("AGENT_TRUST_SUPPLY_DATABASE_CA_FILE")?;
    let options=database_options(&database_url,&database_password,&database_ca,&expected_role)?;
    database_password.zeroize();
    let pool=PgPoolOptions::new().min_connections(2).max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(5)).connect_with(options).await?;
    verify_database_role(&pool,&expected_role).await?;

    let outbound=outbound_client(
        &required_path("AGENT_TRUST_SUPPLY_OUTBOUND_CA_FILE")?,
        &required_path("AGENT_TRUST_SUPPLY_OUTBOUND_CERTIFICATE_FILE")?,
        &required_private_path("AGENT_TRUST_SUPPLY_OUTBOUND_PRIVATE_KEY_FILE")?,
    )?;
    let coordinator=dependency("COORDINATOR")?;
    let dependencies=vec![
        dependency("REPOSITORY")?,dependency("SIGNER")?,dependency("SCANNER")?,
        dependency("SANDBOX")?,dependency("REVOCATION")?,dependency("EVIDENCE")?,
    ];
    let evidence_keyring=EvidenceEventKeyring::from_json(&std::fs::read(required_private_path("AGENT_TRUST_SUPPLY_EVIDENCE_KEYRING_FILE")?)?)?;
    let evidence_client_identity=required_identifier("AGENT_TRUST_SUPPLY_EVIDENCE_CLIENT_IDENTITY")?;
    let runtime=Arc::new(HttpSupplyChainRuntimePort::new(outbound,coordinator,dependencies,evidence_keyring,evidence_client_identity)?);
    let keyring=SupplyReceiptKeyring::from_json(
        &std::fs::read(required_private_path("AGENT_TRUST_SUPPLY_RECEIPT_KEYRING_FILE")?)?,
        chrono::Utc::now(),
    )?;
    let authority=SupplyChainAuthority::new(
        PostgresSupplyChainStore::new(pool),runtime,keyring,
        Uuid::parse_str(&required_uuid("AGENT_TRUST_SUPPLY_INSTANCE_ID")?)?,
        required_i64("AGENT_TRUST_SUPPLY_EXECUTION_LEASE_SECONDS",15,300)?,
    )?;
    let identities=required_identities("AGENT_TRUST_SUPPLY_CLIENT_IDENTITIES")?;
    let tokens=Arc::new(SupplyTokenAuthorizer::from_file(
        &required_private_path("AGENT_TRUST_SUPPLY_TOKEN_BINDINGS_FILE")?,&identities,
    )?);
    let application=router(authority.clone(),tokens);
    let data_port=required_i64("AGENT_TRUST_SUPPLY_PORT",8093,8093)? as u16;
    let management_port=required_i64("AGENT_TRUST_SUPPLY_MANAGEMENT_PORT",9103,9103)? as u16;
    serve(SupplyServerConfig{
        data_address:SocketAddr::new(env::var("AGENT_TRUST_SUPPLY_LISTEN_ADDRESS")?.parse::<IpAddr>()?,data_port),
        management_address:SocketAddr::new(env::var("AGENT_TRUST_SUPPLY_MANAGEMENT_LISTEN_ADDRESS")?.parse::<IpAddr>()?,management_port),
        tls_ca_file:required_path("AGENT_TRUST_SUPPLY_TLS_CA_FILE")?,
        tls_certificate_file:required_path("AGENT_TRUST_SUPPLY_TLS_CERTIFICATE_FILE")?,
        tls_private_key_file:required_private_path("AGENT_TRUST_SUPPLY_TLS_PRIVATE_KEY_FILE")?,
        allowed_client_identities:identities,
    },application,authority).await?;
    Ok(())
}

fn dependency(suffix:&str)->Result<SupplyDependency,Box<dyn std::error::Error>>{
    Ok(SupplyDependency{
        name:suffix.to_ascii_lowercase(),
        endpoint:required_url(&format!("AGENT_TRUST_SUPPLY_{suffix}_ENDPOINT"))?,
        token_file:required_private_path(&format!("AGENT_TRUST_SUPPLY_{suffix}_TOKEN_FILE"))?,
        readiness_schema:env::var(format!("AGENT_TRUST_SUPPLY_{suffix}_READINESS_SCHEMA"))?,
    })
}

async fn verify_database_role(pool:&sqlx::PgPool,expected:&str)->Result<(),Box<dyn std::error::Error>>{
    let row=sqlx::query("SELECT current_user AS role_name,rolsuper,rolbypassrls,rolcreatedb,rolcreaterole,
        rolreplication,rolinherit,rolcanlogin,current_setting('search_path') AS search_path,
        current_schemas(true)::text AS schemas,current_setting('row_security') AS row_security,
        has_schema_privilege(current_user,'public','CREATE') AS can_create,
        has_database_privilege(current_user,current_database(),'TEMP') AS can_temp
        FROM pg_roles WHERE rolname=current_user").fetch_one(pool).await?;
    if row.try_get::<String,_>("role_name")?!=expected||row.try_get::<bool,_>("rolsuper")?
        ||row.try_get::<bool,_>("rolbypassrls")?||row.try_get::<bool,_>("rolcreatedb")?
        ||row.try_get::<bool,_>("rolcreaterole")?||row.try_get::<bool,_>("rolreplication")?
        ||row.try_get::<bool,_>("rolinherit")?||!row.try_get::<bool,_>("rolcanlogin")?
        ||row.try_get::<String,_>("search_path")?!="pg_catalog, public"
        ||row.try_get::<String,_>("schemas")?!="{pg_catalog,public}"
        ||row.try_get::<String,_>("row_security")?!="on"||row.try_get::<bool,_>("can_create")?
        ||row.try_get::<bool,_>("can_temp")?{return Err("SUPPLY_CHAIN_DATABASE_ROLE_UNSAFE".into());}
    Ok(())
}

fn database_options(value:&str,password:&str,ca_file:&Path,expected_role:&str)->Result<PgConnectOptions,Box<dyn std::error::Error>>{
    let parsed=url::Url::parse(value)?;let mut query=std::collections::BTreeMap::new();
    for(key,value)in parsed.query_pairs(){let normalized=key.to_ascii_lowercase();if key.as_ref()!=normalized||value.is_empty()||query.insert(normalized,value.into_owned()).is_some(){return Err("SUPPLY_CHAIN_DATABASE_URL_INVALID".into());}}
    let database=parsed.path().strip_prefix('/').unwrap_or("");
    if !matches!(parsed.scheme(),"postgres"|"postgresql")||parsed.host_str().is_none()||parsed.username()!=expected_role
        ||parsed.password().is_some()||database.is_empty()||database.len()>63||database.contains('/')||parsed.fragment().is_some()
        ||password.is_empty()||query.len()!=2||query.get("sslmode").map(String::as_str)!=Some("verify-full")
        ||query.get("options").map(String::as_str)!=Some("-csearch_path=pg_catalog,public")||!ca_file.is_absolute(){return Err("SUPPLY_CHAIN_DATABASE_URL_INVALID".into());}
    Ok(PgConnectOptions::from_str(value)?.password(password).ssl_mode(PgSslMode::VerifyFull).ssl_root_cert(ca_file))
}

fn outbound_client(ca:&Path,certificate:&Path,private_key:&Path)->Result<reqwest::Client,Box<dyn std::error::Error>>{
    let ca=Certificate::from_pem(&std::fs::read(ca)?)?;let mut identity_pem=std::fs::read(certificate)?;let mut key=std::fs::read(private_key)?;
    identity_pem.extend_from_slice(b"\n");identity_pem.extend_from_slice(&key);key.zeroize();let identity=Identity::from_pem(&identity_pem)?;identity_pem.zeroize();
    Ok(reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(ca).identity(identity).connect_timeout(std::time::Duration::from_secs(5)).timeout(std::time::Duration::from_secs(45)).build()?)
}

fn required_path(name:&str)->Result<PathBuf,Box<dyn std::error::Error>>{let path=PathBuf::from(env::var(name)?);if !path.is_absolute()||!secure_file(&path,false)?{return Err("SUPPLY_CHAIN_REQUIRED_FILE_INVALID".into());}Ok(path)}
fn required_private_path(name:&str)->Result<PathBuf,Box<dyn std::error::Error>>{let path=PathBuf::from(env::var(name)?);if !path.is_absolute()||!secure_file(&path,true)?{return Err("SUPPLY_CHAIN_PRIVATE_FILE_INVALID".into());}Ok(path)}
fn secure_file(path:&Path,private:bool)->Result<bool,Box<dyn std::error::Error>>{let metadata=std::fs::symlink_metadata(path)?;let mode=metadata.mode()&0o777;let uid=nix::unistd::Uid::effective().as_raw();let gid=nix::unistd::Gid::effective().as_raw();let access=if private{let allowed=0o400|if metadata.gid()==gid{0o040}else{0};let readable=(metadata.uid()==uid&&mode&0o400!=0)||(metadata.gid()==gid&&mode&0o040!=0);readable&&mode&!allowed==0}else{mode&0o022==0};Ok(metadata.file_type().is_file()&&!metadata.file_type().is_symlink()&&metadata.nlink()==1&&metadata.len()>0&&metadata.len()<=16*1024*1024&&access)}
fn read_secret_file(name:&str,minimum:usize,maximum:usize)->Result<String,Box<dyn std::error::Error>>{let value=std::fs::read_to_string(required_private_path(name)?)?;let secret=value.trim_end_matches(['\r','\n']);if !(minimum..=maximum).contains(&secret.len())||secret.bytes().any(|byte|!byte.is_ascii_graphic())||value.len().saturating_sub(secret.len())>2{return Err("SUPPLY_CHAIN_SECRET_FILE_INVALID".into());}Ok(secret.to_string())}
fn required_url(name:&str)->Result<url::Url,Box<dyn std::error::Error>>{let value=url::Url::parse(&env::var(name)?)?;if value.scheme()!="https"||value.host_str().is_none()||!value.username().is_empty()||value.password().is_some()||value.path()!="/"||value.query().is_some()||value.fragment().is_some(){return Err("SUPPLY_CHAIN_ENDPOINT_INVALID".into());}Ok(value)}
fn required_identifier(name:&str)->Result<String,Box<dyn std::error::Error>>{let value=env::var(name)?;if value.is_empty()||value.len()>256||value.bytes().any(|byte|!(byte.is_ascii_alphanumeric()||matches!(byte,b'-'|b'_'|b'.'|b':'|b'/'|b'@'))){return Err("SUPPLY_CHAIN_IDENTIFIER_INVALID".into());}Ok(value)}
fn required_uuid(name:&str)->Result<String,Box<dyn std::error::Error>>{let value=env::var(name)?;if !Uuid::parse_str(&value).is_ok_and(|parsed|parsed.to_string()==value){return Err("SUPPLY_CHAIN_UUID_INVALID".into());}Ok(value)}
fn required_i64(name:&str,minimum:i64,maximum:i64)->Result<i64,Box<dyn std::error::Error>>{let value:i64=env::var(name)?.parse()?;if !(minimum..=maximum).contains(&value){return Err("SUPPLY_CHAIN_INTEGER_INVALID".into());}Ok(value)}
fn required_identities(name:&str)->Result<BTreeSet<String>,Box<dyn std::error::Error>>{let parsed=env::var(name)?.split(',').map(str::trim).map(str::to_string).collect::<BTreeSet<_>>();if parsed.is_empty()||parsed.len()>64||parsed.iter().any(|identity|identity.len()>512||!(identity.starts_with("DNS:")||identity.starts_with("URI:"))||identity.split_once(':').is_none_or(|(_,value)|value.is_empty()||!value.bytes().all(|byte|byte.is_ascii_graphic()))){return Err("SUPPLY_CHAIN_CLIENT_IDENTITIES_INVALID".into());}Ok(parsed)}
