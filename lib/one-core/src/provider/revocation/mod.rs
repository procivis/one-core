use crate::model::credential::Credential;
use crate::provider::credential_formatter::model::{CredentialStatus, IssuerDetails};
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, RevocationMethodCapabilities, RevocationUpdate,
};

pub mod bitstring_status_list;
pub mod error;
pub mod lvvc;
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
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError>;

    /// Change a credential's status to valid, revoked, or suspended.
    ///
    /// For list-based revocation methods, use `additional_data` to specify the ID of the associated list.
    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError>;

    /// Checks the revocation status of a credential.
    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IssuerDetails,
        additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
    ) -> Result<CredentialRevocationState, RevocationError>;

    /// Revocation method capabilities include the operations possible for each revocation
    /// method.
    fn get_capabilities(&self) -> RevocationMethodCapabilities;

    /// For credentials with LVVC revocation method, this method creates the URL
    /// where the JSON-LD @context is hosted.
    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError>;

    fn get_params(&self) -> Result<serde_json::Value, RevocationError>;
}
