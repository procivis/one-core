use std::fmt::{Display, Formatter};

use proc_macros::provider_mock;
use shared_types::{RevocationListEntryId, RevocationListId, RevocationMethodId, SignerId};

use self::error::RevocationError;
use self::model::{
    CredentialDataByRole, CredentialRevocationInfo, RevocationMethodCapabilities, RevocationState,
};
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::managed_instance_attestation::{
    ManagedInstanceAttestation, ManagedInstanceAttestationRevocationInfo,
};
use crate::provider::Provider;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};

pub mod bitstring_status_list;
pub mod crl;
mod decorators;
pub mod error;
pub mod mapper;
pub mod model;
pub mod provider;
pub mod status_list_2021;
pub mod token_status_list;
mod utils;

#[provider_mock]
#[async_trait::async_trait]
pub trait RevocationMethod: Provider + Send + Sync {
    /// Returns the revocation method as a string for the `credentialStatus` field of the VC.
    fn get_status_type(&self) -> String;

    /// Creates the `credentialStatus` field of the VC.
    ///
    /// For BitstringStatusList, this method creates the entry in revocation and suspension lists.
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
        attestation: &ManagedInstanceAttestation,
    ) -> Result<CredentialRevocationInfo, RevocationError>;

    /// Issuer: construct status block to be included in a re-issued attestion JWT
    async fn get_attestation_revocation_info(
        &self,
        key_info: &ManagedInstanceAttestationRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError>;

    /// Issuer: update precomputed revocation credential with latest changes considering input attestations
    async fn update_attestation_entries(
        &self,
        keys: Vec<ManagedInstanceAttestationRevocationInfo>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError>;

    // Signature functionality

    /// Issuer: create a status list entry before generating signature
    async fn add_signature<'a>(
        &self,
        signature_type: SignerId,
        issuer: &'a Identifier,
        certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError>;

    /// Issuer: mark previously-issued signature as revoked
    async fn revoke_signature(
        &self,
        signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError>;

    /// Issuer: get an up-to-date revocation list
    async fn get_updated_list(&self, list_id: RevocationListId)
    -> Result<Vec<u8>, RevocationError>;

    /// Revocation method capabilities include the operations possible for each revocation
    /// method.
    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    fn config_name(&self) -> &RevocationMethodId;
}

impl Display for dyn RevocationMethod {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Revocation method `{}`", self.config_name())
    }
}
