//! Implementation of ISO mDL (ISO/IEC 18013-5:2021).
//! https://www.iso.org/standard/69084.html

use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use shared_types::RevocationListEntryId;

use super::model::{CredentialRevocationInfo, Operation};
use crate::model::certificate::Certificate;
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

#[serde_with::serde_as]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub refresh_interval: time::Duration,
}

pub struct CRLRevocation {
    #[expect(dead_code)]
    params: Params,
}

impl CRLRevocation {
    pub fn new(params: Params) -> Self {
        Self { params }
    }
}

#[async_trait::async_trait]
impl RevocationMethod for CRLRevocation {
    fn get_status_type(&self) -> String {
        "CRL".to_string()
    }

    async fn add_issued_credential(
        &self,
        _credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: credential revocation not supported".to_string(),
        ))
    }

    async fn mark_credential_as(
        &self,
        _credential: &Credential,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: credential revocation not supported".to_string(),
        ))
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        _force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: credential revocation not supported".to_string(),
        ))
    }

    async fn add_issued_attestation(
        &self,
        _attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: attestation revocation not supported".to_string(),
        ))
    }

    async fn get_attestation_revocation_info(
        &self,
        _key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: attestation revocation not supported".to_string(),
        ))
    }

    async fn update_attestation_entries(
        &self,
        _keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: attestation revocation not supported".to_string(),
        ))
    }

    async fn add_signature(
        &self,
        _signature_type: String,
        _issuer: &Identifier,
        _certificate: &Option<Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        todo!()
    }

    async fn revoke_signature(
        &self,
        _signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        todo!()
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "CRL: json_ld not supported".to_string(),
        ))
    }
}
