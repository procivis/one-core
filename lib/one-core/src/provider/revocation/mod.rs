use shared_types::RevocationListEntryId;

use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, JsonLdContext, RevocationMethodCapabilities,
    RevocationState,
};

pub mod bitstring_status_list;
pub mod crl;
pub mod error;
pub mod lvvc;
mod mapper;
pub mod mdoc_mso_update_suspension;
pub mod model;
pub mod none;
pub mod provider;
pub mod status_list_2021;
pub mod token_status_list;
mod utils;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait RevocationMethod: Send + Sync {
    /// Returns the revocation method as a string for the `credentialStatus` field of the VC.
    fn get_status_type(&self) -> String;

    /// Creates the `credentialStatus` field of the VC.
    ///
    /// For BitstringStatusList, this method creates the entry in revocation and suspension lists.
    ///
    /// For LVVC, the URL used by the holder to obtain a new LVVC is returned.
    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError>;

    /// Change a credential's status to valid, revoked, or suspended.
    ///
    /// For list-based revocation methods, use `additional_data` to specify the ID of the associated list.
    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: RevocationState,
    ) -> Result<(), RevocationError>;

    /// Checks the revocation status of a credential.
    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError>;

    // wallet unit attestation functionality

    /// Issuer: place issued attestation on a status-list
    async fn add_issued_attestation(
        &self,
        attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError>;

    /// Issuer: construct status block to be included in a re-issued attestion JWT
    async fn get_attestation_revocation_info(
        &self,
        key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError>;

    /// Issuer: update precomputed revocation credential with latest changes considering input attestations
    async fn update_attestation_entries(
        &self,
        keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError>;

    // Signature functionality

    /// Issuer: create a status list entry before generating signature
    async fn add_signature(
        &self,
        signature_type: String,
        issuer: &Identifier,
        certificate: &Option<Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError>;

    /// Issuer: mark previously-issued signature as revoked
    async fn revoke_signature(
        &self,
        signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError>;

    /// Revocation method capabilities include the operations possible for each revocation
    /// method.
    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    /// For credentials with LVVC revocation method, this method creates the URL
    /// where the JSON-LD @context is hosted.
    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError>;
}
