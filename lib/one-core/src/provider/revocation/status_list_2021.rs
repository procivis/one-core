use one_providers::credential_formatter::model::CredentialStatus;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use std::sync::Arc;

use crate::model::did::KeyRole;
use crate::provider::credential_formatter::status_list_jwt_formatter::StatusList2021JWTFormatter;
use crate::util::key_verification::KeyVerification;
use one_providers::common_models::credential::OpenCredential;
use one_providers::common_models::did::DidValue;
use one_providers::revocation::error::RevocationError;
use one_providers::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, RevocationMethodCapabilities, RevocationUpdate,
};
use one_providers::revocation::RevocationMethod;
use one_providers::util::bitstring::extract_bitstring_index;

pub struct StatusList2021 {
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

    async fn add_issued_credential(
        &self,
        _credential: &OpenCredential,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "StatusList2021".to_string(),
        ))
    }

    async fn mark_credential_as(
        &self,
        _credential: &OpenCredential,
        _new_state: CredentialRevocationState,
        _additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "StatusList2021".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError> {
        if credential_status.r#type != CREDENTIAL_STATUS_TYPE {
            return Err(RevocationError::ValidationError(format!(
                "Invalid credential status type: {}",
                credential_status.r#type
            )));
        }

        let list_url = credential_status
            .additional_fields
            .get("statusListCredential")
            .and_then(|v| v.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get("statusListIndex")
            .and_then(|v| v.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| RevocationError::ValidationError("Invalid list index".to_string()))?;

        let response = self
            .client
            .get(list_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let encoded_list =
            StatusList2021JWTFormatter::parse_status_list(&response, issuer_did, key_verification)
                .await?;

        if extract_bitstring_index(encoded_list, list_index)? {
            Ok(match credential_status.status_purpose.as_ref() {
                Some(purpose) => match purpose.as_str() {
                    "revocation" => CredentialRevocationState::Revoked,
                    "suspension" => CredentialRevocationState::Suspended {
                        suspend_end_date: None,
                    },
                    _ => {
                        return Err(RevocationError::ValidationError(format!(
                            "Invalid status purpose: {purpose}",
                        )))
                    }
                },
                None => {
                    return Err(RevocationError::ValidationError(
                        "Missing status purpose ".to_string(),
                    ))
                }
            })
        } else {
            Ok(CredentialRevocationState::Valid)
        }
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }
}
