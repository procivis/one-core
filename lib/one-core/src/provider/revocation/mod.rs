use std::fmt::{Display, Formatter};

use proc_macros::provider_mock;
use shared_types::{RevocationListEntryId, RevocationListId, RevocationMethodId, SignerId};

use self::error::RevocationError;
use self::model::{
    CredentialRevocationInfo, ReservedEntries, RevocationMethodCapabilities, RevocationState,
};
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::managed_instance_attestation::ManagedInstanceAttestation;
use crate::model::revocation_list::UpdateRevocationListEntryId;
use crate::provider::Provider;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};

pub mod bitstring_status_list;
pub mod crl;
mod decorators;
pub mod error;
pub mod mapper;
pub mod model;
pub mod provider;
mod status_list;
pub mod status_list_2021;
pub mod token_status_list;
mod utils;

#[provider_mock]
#[async_trait::async_trait]
pub trait RevocationMethod: Provider + Send + Sync {
    /// For selecting a matching revocation method
    fn can_check_status(&self, credential_status: &CredentialStatus) -> bool;

    /// Creates the `credentialStatus` field of the VC.
    ///
    /// For list-based revocation methods, this method reserves the entries in the status lists
    /// (for BitstringStatusList in revocation and suspension lists). The entries are not linked
    /// to the credential, so it does not need to be persisted yet, see [`ReservedEntries`].
    async fn reserve_credential_entries(
        &self,
        credential: &Credential,
    ) -> Result<ReservedEntries, RevocationError>;

    /// Issuer: set the state of existing list entries (valid, revoked or suspended) and
    /// republish every affected list.
    ///
    /// Entries can be addressed by credential, by entry id or by list index. The lists are
    /// re-rendered with the issuer identifier and certificate stored on the list.
    async fn set_entries_state(
        &self,
        entries: Vec<UpdateRevocationListEntryId>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError>;

    /// Checks the revocation status of a credential.
    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError>;

    // wallet unit attestation functionality

    /// Issuer: place issued attestation on a status-list
    async fn add_issued_attestation(
        &self,
        attestation: &ManagedInstanceAttestation,
    ) -> Result<CredentialRevocationInfo, RevocationError>;

    // Signature functionality

    /// Issuer: create a status list entry before generating signature
    async fn add_signature<'a>(
        &self,
        signature_type: SignerId,
        issuer: &'a Identifier,
        certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError>;

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
