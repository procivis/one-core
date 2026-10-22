use std::sync::Arc;

use one_core::proto::native_credential_manager::{
    DigitalCredentialClaim, DigitalCredentialDisplay, DigitalCredentialMetadata,
    DigitalCredentialRegistration,
};
use one_dto_mapper::{From, convert_inner};

use crate::error::CredentialManagerError;

mod imp;

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DigitalCredentialRegistration)]
#[uniffi(name = "DigitalCredentialRegistration")]
pub struct DigitalCredentialRegistrationBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub credential_id: String,
    pub metadata: DigitalCredentialMetadataBindingEnum,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<DigitalCredentialClaimBindingDTO>,
    pub display: DigitalCredentialDisplayBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DigitalCredentialClaim)]
#[uniffi(name = "DigitalCredentialClaim")]
pub struct DigitalCredentialClaimBindingDTO {
    pub path: Vec<String>,
    pub display_name: Option<String>,
    pub selectively_disclosable: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DigitalCredentialDisplay)]
#[uniffi(name = "DigitalCredentialDisplay")]
pub struct DigitalCredentialDisplayBindingDTO {
    pub credential_name: String,
    pub issuer_name: Option<String>,
    pub logo: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(DigitalCredentialMetadata)]
#[uniffi(name = "DigitalCredentialMetadata")]
pub enum DigitalCredentialMetadataBindingEnum {
    SdJwtVc { vct: String },
    Mdoc { doctype: String },
}

/// Provider of native credential manager (for DC-API)
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait CredentialManager: Send + Sync {
    /// register credentials in the native credential manager
    /// while removing any previous credential registrations
    async fn synchronize(
        &self,
        credentials: Vec<DigitalCredentialRegistrationBindingDTO>,
    ) -> Result<(), CredentialManagerError>;
}

pub struct CredentialManagerWrapper(pub Arc<dyn CredentialManager>);

/// Native handler of proof submission/rejection
#[uniffi::export(with_foreign)]
pub trait DcApiResponseHandler: Send + Sync {
    /// Called when user accepts proof
    /// - `response`:
    ///   - ISO 18013-7 Annex C: `Base64EncryptedResponse`
    ///   - OpenID4VP DC-API: credentialJson (<https://developer.android.com/reference/kotlin/androidx/credentials/DigitalCredential#credentialJson()>)
    fn on_submit(&self, response: String) -> Result<(), CredentialManagerError>;

    /// Called when user rejects proof
    fn on_reject(&self) -> Result<(), CredentialManagerError>;
}

pub struct DcApiResponseHandlerWrapper(pub Arc<dyn DcApiResponseHandler>);
