use std::sync::Arc;

use shared_types::RevocationListEntryId;

use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::did::KeyRole;
use crate::model::identifier::Identifier;
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::credential_formatter::status_list_jwt_formatter::StatusList2021JWTFormatter;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::bitstring_status_list::util::extract_bitstring_index;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, JsonLdContext, Operation,
    RevocationMethodCapabilities, RevocationState,
};
use crate::provider::revocation::utils::status_purpose_to_revocation_state;

pub struct StatusList2021 {
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub client: Arc<dyn HttpClient>,
    pub certificate_validator: Arc<dyn CertificateValidator>,
}

const CREDENTIAL_STATUS_TYPE: &str = "StatusList2021Entry";

#[async_trait::async_trait]
impl RevocationMethod for StatusList2021 {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "StatusList2021".to_string(),
        ))
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "StatusList2021".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        _force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        let IdentifierDetails::Did(issuer_did) = issuer_details else {
            return Err(RevocationError::ValidationError(
                "issuer did is missing".to_string(),
            ));
        };

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

        let response = self.client.get(list_url).send().await?.error_for_status()?;

        let token = String::from_utf8(response.body)
            .map_err(|e| RevocationError::ValidationError(e.to_string()))?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        let encoded_list =
            StatusList2021JWTFormatter::parse_status_list(&token, issuer_did, key_verification)
                .await?;

        if extract_bitstring_index(encoded_list, list_index)? {
            status_purpose_to_revocation_state(credential_status.status_purpose.as_ref())
        } else {
            Ok(RevocationState::Valid)
        }
    }

    async fn add_issued_attestation(
        &self,
        _attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn get_attestation_revocation_info(
        &self,
        _key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn update_attestation_entries(
        &self,
        _keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn add_signature(
        &self,
        _signature_type: String,
        _issuer: &Identifier,
        _certificate: &Option<Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    async fn revoke_signature(
        &self,
        _signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke, Operation::Suspend],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }
}
