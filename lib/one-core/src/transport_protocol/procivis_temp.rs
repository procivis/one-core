use std::collections::HashMap;

use async_trait::async_trait;

use super::{InvitationResponse, TransportProtocol, TransportProtocolError};
use crate::data_model::HandleInvitationConnectRequest;

pub struct ProcivisTemp {
    client: reqwest::Client,
}

impl Default for ProcivisTemp {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

enum InvitationType {
    CredentialIssuance,
    ProofRequest,
}

fn categorize_url(url: &str) -> Result<InvitationType, TransportProtocolError> {
    let query: HashMap<String, String> = reqwest::Url::parse(url)
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

    if query.contains_key("credential") {
        return Ok(InvitationType::CredentialIssuance);
    } else if query.contains_key("proof") {
        return Ok(InvitationType::ProofRequest);
    }

    Err(TransportProtocolError::Failed("Invalid Query".to_owned()))
}

#[async_trait]
impl TransportProtocol for ProcivisTemp {
    async fn handle_invitation(
        &self,
        url: &str,
        own_did: &str,
    ) -> Result<InvitationResponse, TransportProtocolError> {
        let invitation_type = categorize_url(url)?;

        let request_body = HandleInvitationConnectRequest {
            did: own_did.to_owned(),
        };
        let response = self
            .client
            .post(url)
            .body(serde_json::to_string(&request_body).unwrap())
            .header("content-type", "application/json")
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response = response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response_value = response
            .text()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(match invitation_type {
            InvitationType::CredentialIssuance => InvitationResponse::Credential(
                serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)?,
            ),
            InvitationType::ProofRequest => InvitationResponse::Proof(
                serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)?,
            ),
        })
    }
}
