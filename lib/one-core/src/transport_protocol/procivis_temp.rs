use async_trait::async_trait;

use super::{TransportProtocol, TransportProtocolError};
use crate::data_model::{ConnectIssuerResponse, HandleInvitationConnectRequest};

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

#[async_trait]
impl TransportProtocol for ProcivisTemp {
    async fn handle_invitation(
        &self,
        url: &str,
        own_did: &str,
    ) -> Result<ConnectIssuerResponse, TransportProtocolError> {
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
        Ok(serde_json::from_str(&response_value).map_err(TransportProtocolError::JsonError)?)
    }

    fn send(&self, _input: &str) -> Result<(), TransportProtocolError> {
        Ok(())
    }
    fn handle_message(&self, _message: &str) -> Result<(), TransportProtocolError> {
        Ok(())
    }
}
