use shared_types::RevocationListEntryId;

use super::model::CredentialRevocationInfo;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, JsonLdContext, RevocationMethodCapabilities, RevocationState,
};

pub struct NoneRevocation {}

#[async_trait::async_trait]
impl RevocationMethod for NoneRevocation {
    fn get_status_type(&self) -> String {
        "NONE".to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError> {
        Ok(vec![])
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::ValidationError(
            "Credential cannot be revoked, reactivated or suspended".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        _force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        Err(RevocationError::ValidationError(
            "Credential cannot be revoked - status invalid".to_string(),
        ))
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
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    async fn revoke_signature(
        &self,
        _signature_type: String,
        _signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities { operations: vec![] }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }

    fn get_params(&self) -> Result<serde_json::Value, RevocationError> {
        Ok(serde_json::json!({}))
    }
}
