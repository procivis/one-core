use std::str::FromStr;

use async_trait::async_trait;
use axum::extract::Query;
use axum::http::Uri;

use super::{InvitationResponse, TransportProtocol, TransportProtocolError};
use crate::data_model::{HandleInvitationConnectRequest, HandleInvitationQueryRequest};

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
    let uri = Uri::from_str(url)
        .map_err(|_e| TransportProtocolError::Failed("Invalid URL".to_string()))?;
    let result: Query<HandleInvitationQueryRequest> =
        Query::try_from_uri(&uri).map_err(TransportProtocolError::QueryRejection)?;

    if result.credential.is_some() {
        return Ok(InvitationType::CredentialIssuance);
    } else if result.proof.is_some() {
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
