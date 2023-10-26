use super::{
    dto::{HandleInvitationConnectRequest, InvitationResponse, SubmitIssuerResponse},
    TransportProtocol, TransportProtocolError,
};
use crate::model::{credential::Credential, did::Did, proof::Proof};
use async_trait::async_trait;
use std::collections::HashMap;

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
    ProofRequest { proof_id: String },
}

fn categorize_url(url: &str) -> Result<InvitationType, TransportProtocolError> {
    let query: HashMap<String, String> = reqwest::Url::parse(url)
        .map_err(|e| TransportProtocolError::Failed(e.to_string()))?
        .query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();

    if query.contains_key("credential") {
        return Ok(InvitationType::CredentialIssuance);
    } else if let Some(proof) = query.get("proof") {
        return Ok(InvitationType::ProofRequest {
            proof_id: proof.to_owned(),
        });
    }

    Err(TransportProtocolError::Failed("Invalid Query".to_owned()))
}

#[async_trait]
impl TransportProtocol for ProcivisTemp {
    fn detect_invitation_type(
        &self,
        url: &str,
    ) -> Option<crate::provider::transport_protocol::dto::InvitationType> {
        let r#type = categorize_url(url).ok()?;
        Some(match r#type {
            InvitationType::CredentialIssuance => {
                crate::provider::transport_protocol::dto::InvitationType::CredentialIssuance
            }
            InvitationType::ProofRequest { .. } => {
                crate::provider::transport_protocol::dto::InvitationType::ProofRequest
            }
        })
    }

    async fn handle_invitation(
        &self,
        url: &str,
        own_did: &Did,
    ) -> Result<InvitationResponse, TransportProtocolError> {
        let invitation_type = categorize_url(url)?;

        let request_body = HandleInvitationConnectRequest {
            did: own_did.did.to_owned(),
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
            InvitationType::ProofRequest { proof_id } => InvitationResponse::Proof {
                proof_request: serde_json::from_str(&response_value)
                    .map_err(TransportProtocolError::JsonError)?,
                proof_id,
            },
        })
    }

    async fn reject_proof(&self, proof: &Proof) -> Result<(), TransportProtocolError> {
        let mut url = super::get_base_url(&proof.interaction)?;
        url.set_path("/ssi/temporary-verifier/v1/reject");
        url.set_query(Some(&format!("proof={}", proof.id)));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn submit_proof(
        &self,
        proof: &Proof,
        presentation: &str,
    ) -> Result<(), TransportProtocolError> {
        let mut url = super::get_base_url(&proof.interaction)?;
        url.set_path("/ssi/temporary-verifier/v1/submit");
        url.set_query(Some(&format!("proof={}", proof.id)));

        let response = self
            .client
            .post(url)
            .body(presentation.to_owned())
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn accept_credential(
        &self,
        credential: &Credential,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
        let mut url = super::get_base_url(&credential.interaction)?;
        url.set_path("/ssi/temporary-issuer/v1/submit");
        url.set_query(Some(&format!("credentialId={}", credential.id)));

        let response = self
            .client
            .post(url)
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

        serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)
    }

    async fn reject_credential(
        &self,
        credential: &Credential,
    ) -> Result<(), TransportProtocolError> {
        let mut url = super::get_base_url(&credential.interaction)?;
        url.set_path("/ssi/temporary-issuer/v1/reject");
        url.set_query(Some(&format!("credentialId={}", credential.id)));

        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;

        Ok(())
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
    ) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }

    async fn share_proof(&self, _proof: &Proof) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }
}
