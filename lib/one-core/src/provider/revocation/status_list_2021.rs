use one_providers::credential_formatter::model::CredentialStatus;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use std::sync::Arc;

use anyhow::Context;
use shared_types::DidValue;

use crate::model::credential::Credential;
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::status_list_jwt_formatter::StatusList2021JWTFormatter;
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::provider::revocation::{
    CredentialDataByRole, CredentialRevocationInfo, CredentialRevocationState, JsonLdContext,
    RevocationMethod, RevocationMethodCapabilities,
};
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
    ) -> Result<Vec<CredentialRevocationInfo>, ServiceError> {
        Err(BusinessLogicError::StatusList2021NotSupported.into())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, ServiceError> {
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
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response_value = response
            .text()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

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

        if extract_bitstring_index(encoded_list, list_index)? {
            Ok(match credential_status.status_purpose.as_ref() {
                Some(purpose) => match purpose.as_str() {
                    "revocation" => CredentialRevocationState::Revoked,
                    "suspension" => CredentialRevocationState::Suspended {
                        suspend_end_date: None,
                    },
                    _ => {
                        return Err(ServiceError::ValidationError(format!(
                            "Invalid status purpose: {purpose}",
                        )))
                    }
                },
                None => {
                    return Err(ServiceError::ValidationError(
                        "Missing status purpose ".to_string(),
                    ))
                }
            })
        } else {
            Ok(CredentialRevocationState::Valid)
        }
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: CredentialRevocationState,
    ) -> Result<(), ServiceError> {
        Err(BusinessLogicError::StatusList2021NotSupported.into())
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, ServiceError> {
        Ok(JsonLdContext::default())
    }
}
