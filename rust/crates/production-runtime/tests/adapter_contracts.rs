use agent_trust_agent_registry_posture::LifecyclePropagationPort;
use agent_trust_enterprise_approval::NotificationAdapter;
use agent_trust_enterprise_control::{AuthoritativeServicePort, IntegrationPort};
use agent_trust_gateway::{IdentityVerifierPort, OrchestratorSubmissionPort};
use agent_trust_identity::FederatedTrustBundleProvider;
use agent_trust_incident_release_gate::{ContainmentPort, RecertificationPort};
use agent_trust_industrial_edge_gateway::IndustrialAdapter;
use agent_trust_mcp_security_proxy::ControlledMcpTransport;
use agent_trust_model_gateway::{ModelProviderAdapter, ProviderWireTransport};
use agent_trust_platform_sre::BackupPort;
use agent_trust_policy_administration::authority::{
    HttpPepPolicyActivationClient, PolicyActivationPort,
};
use agent_trust_policy_pep::RuntimeControlPort;
use agent_trust_production_closure::EvidenceSourcePort;
use agent_trust_production_runtime::{
    ProductionAdapterSet, ProductionOrchestratorBinding,
    adapters::{
        ControlledModelTransport, HttpIndustrialAdapter, HttpOrchestratorAdapter,
        ProductionIdentityVerifier, ProductionModelAdapter, RefreshingJwksProvider,
        SecretBrokerCredentialLifecycle,
    },
    ops::{
        FilesystemEvidenceSource, HttpAuthoritativeService, HttpBackupPort, HttpContainmentPort,
        HttpEnterpriseIntegration, HttpLifecyclePropagationPort, HttpNotificationAdapter,
        HttpRecertificationPort, HttpRuntimeControlPort,
    },
    protocols::{A2aPeerClient, A2aSubmission, HttpMcpTransport},
};
use agent_trust_sandbox_runtime::CredentialLifecyclePort;
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

const CONTRACT_JSON: &str = include_str!("adapter-contracts.json");

const EXPECTED_ADAPTERS: [&str; 17] = [
    "identity",
    "orchestrator",
    "model",
    "secret_broker",
    "industrial",
    "backup",
    "policy_activation",
    "containment",
    "recertification",
    "enterprise_integration",
    "authority",
    "notification",
    "evidence",
    "mcp",
    "a2a",
    "runtime_control",
    "lifecycle",
];

const EXPECTED_CONDITIONS: [&str; 17] = [
    "ENTERPRISE_IDP_JWKS",
    "WORKLOAD_MTLS_CA",
    "SECRET_BROKER_DYNAMIC_LEASES",
    "DEDICATED_LINUX_GVISOR",
    "PRODUCTION_MULTIZONE_TEMPORAL",
    "MANAGED_DATABASE_MULTI_ZONE",
    "LOCKED_RETENTION_OBJECT_STORAGE",
    "MODEL_GENERATION_STREAM_DLP_BILLING_RESIDENCY",
    "MCP_REAL_ENDPOINT",
    "A2A_REAL_ENDPOINT",
    "OPCUA_MQTT_MODBUS_REAL_ENDPOINTS",
    "SUPERVISED_PHYSICAL_WRITE",
    "MULTIZONE_CONTROL_PLANE_TOPOLOGY",
    "NETWORK_STORAGE_CONTROL_PLANE_FAULTS",
    "SUSTAINED_PRODUCTION_LOAD",
    "CUSTOMER_EXPERT_INDEPENDENT_ACCEPTANCE",
    "IMMUTABLE_GIT_RELEASE_PROVENANCE",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractManifest {
    schema_version: String,
    external_evidence_required: bool,
    adapters: Vec<AdapterContract>,
    condition_tests: Vec<ConditionContract>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterContract {
    family_id: String,
    adapter: String,
    #[serde(rename = "trait")]
    trait_name: Option<String>,
    #[serde(default)]
    auxiliary_traits: Vec<TraitContract>,
    #[serde(default)]
    inherent_methods: Vec<String>,
    source: String,
    config_binding: ConfigBinding,
    operations: Vec<OperationContract>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraitContract {
    adapter: String,
    #[serde(rename = "trait")]
    trait_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigBinding {
    kind: String,
    selector: String,
    client_identity_required: bool,
    token_required: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationContract {
    scope: String,
    method: String,
    wire_path: String,
    transport_call: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionContract {
    condition_id: String,
    probes: Vec<TestProbe>,
    #[serde(default)]
    runtime_symbols: Vec<RuntimeSymbols>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestProbe {
    path: String,
    test: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSymbols {
    path: String,
    symbols: Vec<String>,
}

fn manifest() -> ContractManifest {
    serde_json::from_str(CONTRACT_JSON)
        .unwrap_or_else(|error| panic!("adapter contract JSON must be valid: {error}"))
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap_or_else(|| panic!("crate must remain under rust/crates"))
        .to_path_buf()
}

fn set(values: impl IntoIterator<Item = impl AsRef<str>>) -> BTreeSet<String> {
    values
        .into_iter()
        .map(|value| value.as_ref().to_owned())
        .collect()
}

fn implementation_scope<'a>(source: &'a str, anchor: &str) -> &'a str {
    let anchor_offset = source
        .find(anchor)
        .unwrap_or_else(|| panic!("missing implementation scope: {anchor}"));
    let open_offset = source[anchor_offset..]
        .find('{')
        .map(|offset| anchor_offset + offset)
        .unwrap_or_else(|| panic!("missing opening brace for: {anchor}"));
    let mut depth = 0usize;
    for (relative, byte) in source.as_bytes()[open_offset..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth
                    .checked_sub(1)
                    .unwrap_or_else(|| panic!("unbalanced implementation braces"));
                if depth == 0 {
                    return &source[anchor_offset..=open_offset + relative];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated implementation scope: {anchor}")
}

fn assert_test_declaration(source: &str, test: &str) {
    if source.contains(&format!("def {test}(")) {
        assert!(
            test.starts_with("test_"),
            "Python probe must use test_ naming: {test}"
        );
        return;
    }
    let declaration = format!("fn {test}(");
    let offset = source
        .find(&declaration)
        .unwrap_or_else(|| panic!("missing test declaration: {test}"));
    let prefix = &source[offset.saturating_sub(512)..offset];
    assert!(
        prefix.contains("#[test]") || prefix.contains("#[tokio::test"),
        "Rust probe is not marked as a test: {test}"
    );
}

fn assert_endpoint(value: &Value, binding: &ConfigBinding) {
    let base_url = value
        .get("base_url")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("endpoint base_url must be a string"));
    assert!(base_url.starts_with("https://"), "endpoint must use HTTPS");
    let health = value
        .get("health_path")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("endpoint health_path must be a string"));
    assert!(health.starts_with('/') && !health.starts_with("//") && !health.contains(".."));
    let tls = value
        .get("tls")
        .unwrap_or_else(|| panic!("endpoint TLS configuration is required"));
    assert_absolute(tls.get("ca_bundle"), "CA bundle");
    if binding.client_identity_required {
        assert_absolute(tls.get("client_identity_pem"), "client identity");
    }
    if binding.token_required {
        assert_absolute(tls.get("bearer_token_file"), "bearer token file");
    }
    let timeout = tls
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("bounded endpoint timeout is required"));
    assert!((1..=120_000).contains(&timeout));
}

fn assert_absolute(value: Option<&Value>, label: &str) {
    let path = value
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{label} must be a string"));
    assert!(Path::new(path).is_absolute(), "{label} must be absolute");
}

#[test]
fn compiled_adapter_traits_are_complete() {
    fn identity<T: IdentityVerifierPort>() {}
    fn orchestrator<T: OrchestratorSubmissionPort>() {}
    fn model<T: ModelProviderAdapter>() {}
    fn model_transport<T: ProviderWireTransport>() {}
    fn trust_bundle<T: FederatedTrustBundleProvider>() {}
    fn secret_broker<T: CredentialLifecyclePort>() {}
    fn industrial<T: IndustrialAdapter>() {}
    fn backup<T: BackupPort>() {}
    fn policy_activation<T: PolicyActivationPort>() {}
    fn containment<T: ContainmentPort>() {}
    fn recertification<T: RecertificationPort>() {}
    fn enterprise_integration<T: IntegrationPort>() {}
    fn authority<T: AuthoritativeServicePort>() {}
    fn notification<T: NotificationAdapter>() {}
    fn evidence<T: EvidenceSourcePort>() {}
    fn mcp<T: ControlledMcpTransport>() {}
    fn runtime_control<T: RuntimeControlPort>() {}
    fn lifecycle<T: LifecyclePropagationPort>() {}
    fn send_sync<T: Send + Sync>() {}

    identity::<ProductionIdentityVerifier>();
    trust_bundle::<RefreshingJwksProvider>();
    orchestrator::<HttpOrchestratorAdapter>();
    orchestrator::<ProductionOrchestratorBinding>();
    model::<ProductionModelAdapter>();
    model_transport::<ControlledModelTransport>();
    secret_broker::<SecretBrokerCredentialLifecycle>();
    industrial::<HttpIndustrialAdapter>();
    backup::<HttpBackupPort>();
    policy_activation::<HttpPepPolicyActivationClient>();
    containment::<HttpContainmentPort>();
    recertification::<HttpRecertificationPort>();
    enterprise_integration::<HttpEnterpriseIntegration>();
    authority::<HttpAuthoritativeService>();
    notification::<HttpNotificationAdapter>();
    evidence::<FilesystemEvidenceSource>();
    mcp::<HttpMcpTransport>();
    runtime_control::<HttpRuntimeControlPort>();
    lifecycle::<HttpLifecyclePropagationPort>();
    send_sync::<A2aPeerClient>();
    send_sync::<ProductionAdapterSet>();

    fn assert_a2a_surface(client: &A2aPeerClient, request: &A2aSubmission) {
        drop(client.agent_card("peer"));
        drop(client.submit(request));
        drop(client.stream_snapshot("peer", "remote-task", 0));
    }
    let _surface: fn(&A2aPeerClient, &A2aSubmission) = assert_a2a_surface;

    let contracts = manifest();
    assert_eq!(
        set(contracts.adapters.iter().map(|adapter| &adapter.family_id)),
        set(EXPECTED_ADAPTERS),
    );
    let expected_type_contracts = set([
        "ProductionIdentityVerifier:IdentityVerifierPort",
        "HttpOrchestratorAdapter:OrchestratorSubmissionPort",
        "ProductionModelAdapter:ModelProviderAdapter",
        "SecretBrokerCredentialLifecycle:CredentialLifecyclePort",
        "HttpIndustrialAdapter:IndustrialAdapter",
        "HttpBackupPort:BackupPort",
        "HttpPepPolicyActivationClient:PolicyActivationPort",
        "HttpContainmentPort:ContainmentPort",
        "HttpRecertificationPort:RecertificationPort",
        "HttpEnterpriseIntegration:IntegrationPort",
        "HttpAuthoritativeService:AuthoritativeServicePort",
        "HttpNotificationAdapter:NotificationAdapter",
        "FilesystemEvidenceSource:EvidenceSourcePort",
        "HttpMcpTransport:ControlledMcpTransport",
        "A2aPeerClient:INHERENT",
        "HttpRuntimeControlPort:RuntimeControlPort",
        "HttpLifecyclePropagationPort:LifecyclePropagationPort",
    ]);
    let actual_type_contracts = set(contracts.adapters.iter().map(|adapter| {
        format!(
            "{}:{}",
            adapter.adapter,
            adapter.trait_name.as_deref().unwrap_or("INHERENT")
        )
    }));
    assert_eq!(actual_type_contracts, expected_type_contracts);
    let actual_auxiliary_contracts = set(contracts.adapters.iter().flat_map(|adapter| {
        adapter
            .auxiliary_traits
            .iter()
            .map(|binding| format!("{}:{}", binding.adapter, binding.trait_name))
    }));
    assert_eq!(
        actual_auxiliary_contracts,
        set([
            "RefreshingJwksProvider:FederatedTrustBundleProvider",
            "ProductionOrchestratorBinding:OrchestratorSubmissionPort",
            "ControlledModelTransport:ProviderWireTransport",
        ]),
    );
    let a2a = contracts
        .adapters
        .iter()
        .find(|adapter| adapter.family_id == "a2a")
        .unwrap_or_else(|| panic!("A2A contract is required"));
    assert_eq!(
        set(&a2a.inherent_methods),
        set(["agent_card", "submit", "stream_snapshot"])
    );
}

#[test]
fn endpoint_method_and_source_contracts_are_bound() {
    let root = workspace_root();
    let contracts = manifest();
    for adapter in &contracts.adapters {
        assert!(
            !adapter.operations.is_empty(),
            "{} has no operation contract",
            adapter.family_id
        );
        let path = root.join(&adapter.source);
        assert!(path.starts_with(&root) && path.is_file());
        let source = fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("adapter source must be readable: {error}"));
        for operation in &adapter.operations {
            let scope = implementation_scope(&source, &operation.scope);
            assert!(
                scope.contains(&operation.transport_call),
                "{} {} lacks transport primitive {}",
                adapter.family_id,
                operation.wire_path,
                operation.transport_call,
            );
            assert!(
                scope.contains(&operation.wire_path),
                "{} lacks wire path {} in {}",
                adapter.family_id,
                operation.wire_path,
                operation.scope,
            );
            match operation.method.as_str() {
                "GET" => assert!(operation.transport_call.contains("get_bytes")),
                "POST" => assert!(
                    operation.transport_call.contains("post_json")
                        || operation.transport_call == ".post("
                ),
                "FILE_READ" => assert_eq!(operation.transport_call, "read_json("),
                other => panic!("unsupported machine-checked method: {other}"),
            }
        }
    }
}

#[test]
fn example_configuration_binds_every_adapter_fail_closed() {
    let root = workspace_root();
    let contracts = manifest();
    assert_eq!(
        contracts.schema_version,
        "agenttrust.production-adapter-contracts.v1"
    );
    assert!(contracts.external_evidence_required);
    let config: Value = serde_json::from_slice(
        &fs::read(root.join("config/production-runtime.example.json"))
            .unwrap_or_else(|error| panic!("production runtime example must be readable: {error}")),
    )
    .unwrap_or_else(|error| panic!("production runtime example must be JSON: {error}"));
    assert_eq!(
        config.get("schema_version").and_then(Value::as_str),
        Some("agenttrust.production-runtime-config.v1"),
    );
    assert_eq!(
        config.get("fail_closed").and_then(Value::as_bool),
        Some(true)
    );
    let endpoints = config
        .get("endpoints")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("endpoint map is required"));
    for adapter in &contracts.adapters {
        let binding = &adapter.config_binding;
        match binding.kind.as_str() {
            "endpoint" => assert_endpoint(
                endpoints
                    .get(&binding.selector)
                    .unwrap_or_else(|| panic!("missing endpoint {}", binding.selector)),
                binding,
            ),
            "endpoint_prefix" => {
                let matches: Vec<_> = endpoints
                    .iter()
                    .filter(|(name, _)| name.starts_with(&binding.selector))
                    .collect();
                assert!(
                    !matches.is_empty(),
                    "missing endpoint prefix {}",
                    binding.selector
                );
                for (_, endpoint) in matches {
                    assert_endpoint(endpoint, binding);
                }
            }
            "identity_jwks" => {
                let identity = config
                    .get("identity")
                    .unwrap_or_else(|| panic!("identity configuration is required"));
                let endpoint = identity
                    .get("jwks_endpoint")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("JWKS endpoint is required"));
                assert!(endpoint.starts_with("https://"));
                assert_eq!(
                    identity.get("require_mtls_peer").and_then(Value::as_bool),
                    Some(true)
                );
                assert_absolute(identity.pointer("/jwks_tls/ca_bundle"), "JWKS CA bundle");
            }
            "evidence_files" => {
                let files = config
                    .get("evidence_files")
                    .and_then(Value::as_object)
                    .unwrap_or_else(|| panic!("evidence file configuration is required"));
                assert_eq!(files.len(), 4);
                for value in files.values() {
                    assert_absolute(Some(value), "evidence file");
                }
            }
            "authority_env" => {
                let template = fs::read_to_string(
                    root.join("deploy/kubernetes/production-stack.yaml.tmpl"),
                )
                .unwrap_or_else(|error| panic!("production stack template: {error}"));
                for required in [
                    binding.selector.as_str(),
                    "AGENT_TRUST_POLICY_PEP_ACTIVATION_TOKEN_FILE",
                    "AGENT_TRUST_POLICY_OUTBOUND_CA_FILE",
                    "AGENT_TRUST_POLICY_OUTBOUND_CERTIFICATE_FILE",
                    "AGENT_TRUST_POLICY_OUTBOUND_PRIVATE_KEY_FILE",
                    "AGENT_TRUST_POLICY_PEP_ACTIVATION_VERIFYING_KEY_FILE",
                ] {
                    assert!(template.contains(required), "missing authority binding {required}");
                }
            }
            other => panic!("unsupported configuration binding: {other}"),
        }
    }
}

#[test]
fn every_external_condition_has_a_declared_local_probe_but_remains_external() {
    let root = workspace_root();
    let contracts = manifest();
    assert!(contracts.external_evidence_required);
    assert_eq!(
        set(contracts
            .condition_tests
            .iter()
            .map(|row| &row.condition_id)),
        set(EXPECTED_CONDITIONS),
    );
    let condition_manifest: Value = serde_json::from_slice(
        &fs::read(root.join("config/production-runtime/conditions.json"))
            .unwrap_or_else(|error| panic!("condition manifest must be readable: {error}")),
    )
    .unwrap_or_else(|error| panic!("condition manifest must be JSON: {error}"));
    let rows = condition_manifest
        .get("conditions")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("condition rows are required"));
    for contract in &contracts.condition_tests {
        let row = rows
            .iter()
            .find(|row| {
                row.get("condition_id").and_then(Value::as_str) == Some(&contract.condition_id)
            })
            .unwrap_or_else(|| panic!("missing condition {}", contract.condition_id));
        assert_eq!(
            row.get("external_evidence_required")
                .and_then(Value::as_bool),
            Some(true),
        );
        let declared_tests = set(row
            .get("test_paths")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("condition test paths are required"))
            .iter()
            .filter_map(Value::as_str));
        assert!(!contract.probes.is_empty());
        for probe in &contract.probes {
            assert!(declared_tests.contains(&probe.path));
            let source = fs::read_to_string(root.join(&probe.path))
                .unwrap_or_else(|_| panic!("probe source is unreadable: {}", probe.path));
            assert_test_declaration(&source, &probe.test);
        }
        let declared_runtime = set(row
            .get("runtime_paths")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("condition runtime paths are required"))
            .iter()
            .filter_map(Value::as_str));
        for binding in &contract.runtime_symbols {
            assert!(declared_runtime.contains(&binding.path));
            assert!(!binding.symbols.is_empty());
            let source = fs::read_to_string(root.join(&binding.path))
                .unwrap_or_else(|_| panic!("runtime source is unreadable: {}", binding.path));
            for symbol in &binding.symbols {
                assert!(source.contains(symbol), "missing runtime symbol {symbol}");
            }
        }
    }
}
