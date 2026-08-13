use crate::http::SecureHttpTransport;
use agent_trust_contracts::{EffectClass, TaskId};
use agent_trust_identity::CredentialHandle;
use agent_trust_mcp_security_proxy::{ControlledMcpTransport, McpError, RawMcpResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone)]
pub struct HttpMcpTransport {
    servers: BTreeMap<String, SecureHttpTransport>,
}
impl HttpMcpTransport {
    pub fn new(servers: BTreeMap<String, SecureHttpTransport>) -> Result<Self, McpError> {
        if servers.is_empty() || servers.keys().any(|key| key.is_empty()) {
            Err(McpError::ConfigurationInvalid)
        } else {
            Ok(Self { servers })
        }
    }
}

#[derive(Deserialize)]
struct McpWireResult {
    value: Value,
    observed_effect: EffectClass,
}

#[async_trait]
impl ControlledMcpTransport for HttpMcpTransport {
    async fn call_tool(
        &self,
        server_id: &str,
        tool_name: &str,
        arguments: &Value,
        credential_handle: &CredentialHandle,
    ) -> Result<RawMcpResult, McpError> {
        if tool_name.is_empty() || credential_handle.0.is_empty() {
            return Err(McpError::ArgumentsInvalid);
        }
        let transport = self
            .servers
            .get(server_id)
            .ok_or(McpError::ServerUnavailable)?;
        let response: McpWireResult = transport
            .post_json(
                "/v1/mcp/tools/call",
                &json!({
                    "server_id": server_id, "tool_name": tool_name, "arguments": arguments,
                    "credential_handle": credential_handle.0
                }),
                None,
            )
            .await
            .map_err(|_| McpError::ServerUnavailable)?;
        Ok(RawMcpResult {
            value: response.value,
            observed_effect: response.observed_effect,
        })
    }
}

#[derive(Debug, Error)]
pub enum A2aTransportError {
    #[error("A2A_PEER_CONFIGURATION_INVALID")]
    Configuration,
    #[error("A2A_PEER_UNAVAILABLE")]
    Unavailable,
    #[error("A2A_PEER_RESPONSE_INVALID")]
    ResponseInvalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aSubmission {
    pub peer_id: String,
    pub task_id: TaskId,
    pub delegation_token: String,
    pub action_envelope: Value,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aSubmissionReceipt {
    pub remote_task_id: String,
    pub accepted: bool,
    pub peer_evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct A2aAgentCard {
    pub name: String,
    pub protocol_version: String,
    pub capabilities: Vec<String>,
    pub signing_key_digest: String,
}

#[derive(Clone)]
pub struct A2aPeerClient {
    peers: BTreeMap<String, SecureHttpTransport>,
}
impl A2aPeerClient {
    pub fn new(peers: BTreeMap<String, SecureHttpTransport>) -> Result<Self, A2aTransportError> {
        if peers.is_empty() || peers.keys().any(|key| key.is_empty()) {
            Err(A2aTransportError::Configuration)
        } else {
            Ok(Self { peers })
        }
    }
    pub async fn agent_card(&self, peer_id: &str) -> Result<A2aAgentCard, A2aTransportError> {
        let transport = self
            .peers
            .get(peer_id)
            .ok_or(A2aTransportError::Configuration)?;
        let bytes = transport
            .get_bytes("/.well-known/agent-card.json")
            .await
            .map_err(|_| A2aTransportError::Unavailable)?;
        let card: A2aAgentCard =
            serde_json::from_slice(&bytes).map_err(|_| A2aTransportError::ResponseInvalid)?;
        if card.name.is_empty()
            || card.protocol_version.is_empty()
            || card.capabilities.is_empty()
            || !is_digest(&card.signing_key_digest)
        {
            return Err(A2aTransportError::ResponseInvalid);
        }
        Ok(card)
    }
    pub async fn submit(
        &self,
        request: &A2aSubmission,
    ) -> Result<A2aSubmissionReceipt, A2aTransportError> {
        let transport = self
            .peers
            .get(&request.peer_id)
            .ok_or(A2aTransportError::Configuration)?;
        if request.delegation_token.is_empty() || request.idempotency_key.is_empty() {
            return Err(A2aTransportError::Configuration);
        }
        let receipt: A2aSubmissionReceipt = transport
            .post_json("/v1/a2a/tasks", request, Some(&request.idempotency_key))
            .await
            .map_err(|_| A2aTransportError::Unavailable)?;
        if !receipt.accepted
            || receipt.remote_task_id.is_empty()
            || receipt.peer_evidence_ref.is_empty()
        {
            return Err(A2aTransportError::ResponseInvalid);
        }
        Ok(receipt)
    }
    pub async fn stream_snapshot(
        &self,
        peer_id: &str,
        remote_task_id: &str,
        after_sequence: u64,
    ) -> Result<Vec<Value>, A2aTransportError> {
        let transport = self
            .peers
            .get(peer_id)
            .ok_or(A2aTransportError::Configuration)?;
        #[derive(Deserialize)]
        struct Events {
            events: Vec<Value>,
        }
        let response: Events = transport
            .post_json(
                "/v1/a2a/tasks/stream-snapshot",
                &json!({
                    "remote_task_id": remote_task_id, "after_sequence": after_sequence
                }),
                None,
            )
            .await
            .map_err(|_| A2aTransportError::Unavailable)?;
        if response.events.len() > 10_000 {
            Err(A2aTransportError::ResponseInvalid)
        } else {
            Ok(response.events)
        }
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_card_digest_is_exact_sha256() {
        assert!(is_digest(&"a".repeat(64)));
        assert!(!is_digest(&"a".repeat(63)));
        assert!(!is_digest(&"z".repeat(64)));
    }

    #[test]
    fn empty_peer_sets_fail_closed() {
        assert!(A2aPeerClient::new(BTreeMap::new()).is_err());
        assert!(HttpMcpTransport::new(BTreeMap::new()).is_err());
    }
}
