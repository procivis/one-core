use std::sync::Arc;

use shared_types::DidValue;

use crate::model::credential::Credential;
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::{
    model::CredentialStatus, status_list_jwt_formatter::StatusList2021JWTFormatter,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::{
    CredentialDataByRole, CredentialRevocationInfo, RevocationMethod, RevocationMethodCapabilities,
};
use crate::provider::transport_protocol::TransportProtocolError;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::util::bitstring::extract_bitstring_index;
use crate::util::key_verification::KeyVerification;

pub(crate) struct StatusList2021 {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub client: reqwest::Client,
}

const CREDENTIAL_STATUS_TYPE: &str = "StatusList2021Entry";

#[async_trait::async_trait]
impl RevocationMethod for StatusList2021 {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        Err(BusinessLogicError::StatusList2021NotSupported.into())
    }

    async fn mark_credential_revoked(&self, _credential: &Credential) -> Result<(), ServiceError> {
        Err(BusinessLogicError::StatusList2021NotSupported.into())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<bool, ServiceError> {
        if credential_status.r#type != CREDENTIAL_STATUS_TYPE {
            return Err(ServiceError::ValidationError(format!(
                "Invalid credential status type: {}",
                credential_status.r#type
            )));
        }

        let list_url = credential_status
            .additional_fields
            .get("statusListCredential")
            .ok_or(ServiceError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get("statusListIndex")
            .ok_or(ServiceError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| ServiceError::ValidationError("Invalid list index".to_string()))?;

        let response = self
            .client
            .get(list_url)
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

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let encoded_list = StatusList2021JWTFormatter::parse_status_list(
            &response_value,
            issuer_did,
            key_verification,
        )
        .await?;

        let result = extract_bitstring_index(encoded_list, list_index)?;
        Ok(result)
    }
}
