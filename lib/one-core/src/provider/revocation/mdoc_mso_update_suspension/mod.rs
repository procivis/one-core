//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use super::model::{CredentialRevocationInfo, Operation};
use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationState, JsonLdContext, RevocationMethodCapabilities,
};

pub struct MdocMsoUpdateSuspensionRevocation {}

#[async_trait::async_trait]
impl RevocationMethod for MdocMsoUpdateSuspensionRevocation {
    fn get_status_type(&self) -> String {
        "MDOC_MSO_UPDATE_SUSPENSION".to_string()
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
        new_state: CredentialRevocationState,
    ) -> Result<(), RevocationError> {
        if new_state == CredentialRevocationState::Revoked {
            return Err(RevocationError::OperationNotSupported(
                "MDOC_MSO_UPDATE_SUSPENSION: revocation not supported".to_string(),
            ));
        }

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        _force_refresh: bool,
    ) -> Result<CredentialRevocationState, RevocationError> {
        Err(RevocationError::ValidationError(
            "Credential cannot be revoked - status invalid".to_string(),
        ))
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Suspend],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }

    fn get_params(&self) -> Result<serde_json::Value, RevocationError> {
        Ok(serde_json::json!({}))
    }
}
