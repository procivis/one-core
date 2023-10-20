use super::{
    dto::{HandleInvitationConnectRequest, InvitationResponse, SubmitIssuerResponse},
    TransportProtocol, TransportProtocolError,
};
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
            InvitationType::ProofRequest { proof_id } => InvitationResponse::Proof {
                proof_request: serde_json::from_str(&response_value)
                    .map_err(TransportProtocolError::JsonError)?,
                proof_id,
            },
        })
    }

    async fn reject_proof(
        &self,
        base_url: &str,
        proof_id: &str,
    ) -> Result<(), TransportProtocolError> {
        let mut url = reqwest::Url::parse(base_url)
            .map_err(|_| TransportProtocolError::Failed("Invalid base URL".to_string()))?;
        url.set_path("/ssi/temporary-verifier/v1/reject");
        url.set_query(Some(&format!("proof={proof_id}")));

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
        base_url: &str,
        proof_id: &str,
        presentation: &str,
    ) -> Result<(), TransportProtocolError> {
        let mut url = reqwest::Url::parse(base_url)
            .map_err(|_| TransportProtocolError::Failed("Invalid base URL".to_string()))?;
        url.set_path("/ssi/temporary-verifier/v1/submit");
        url.set_query(Some(&format!("proof={proof_id}")));

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
        base_url: &str,
        credential_id: &str,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
        let mut url = reqwest::Url::parse(base_url)
            .map_err(|_| TransportProtocolError::Failed("Invalid base URL".to_string()))?;
        url.set_path("/ssi/temporary-issuer/v1/submit");
        url.set_query(Some(&format!("credentialId={credential_id}")));

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
        base_url: &str,
        credential_id: &str,
    ) -> Result<(), TransportProtocolError> {
        let mut url = reqwest::Url::parse(base_url)
            .map_err(|_| TransportProtocolError::Failed("Invalid base URL".to_string()))?;
        url.set_path("/ssi/temporary-issuer/v1/reject");
        url.set_query(Some(&format!("credentialId={credential_id}")));

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
}
