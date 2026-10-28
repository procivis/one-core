use std::fmt::{Display, Formatter};
use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::SignerId;

use crate::provider::Provider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::dto::Issuer;
use crate::provider::signer::error::SignerError;

mod access_certificate;
mod decorators;
pub mod dto;
pub mod error;
pub mod model;
pub mod provider;
pub mod registration_certificate;
pub mod swiyu_proof_of_possession;
mod validity;
pub mod x509_certificate;
mod x509_utils;

/// A configured signer: produces a signed output (a certificate, a
/// signed token) from an issuer and signer-specific request data.
///
/// Each signer is created from an entry in the `signer` configuration
/// and wrapped by `provider::signer_provider_from_config` in:
/// - `CapabilityChecked`, which rejects issuers the signer does not
///   support: identifier issuers of an unsupported type, and key issuers
///   with an unsupported key algorithm.
/// - `PermissionChecked`, which enforces `sign_required_permissions`.
///
/// Implementations therefore do not check sign permissions themselves.
/// Revoke permissions are checked by the signature service.
#[provider_mock]
#[async_trait]
pub trait Signer: Provider + Send + Sync {
    /// What the signer supports and requires. Also reported as the
    /// signer's capabilities in the configuration output.
    fn get_capabilities(&self) -> model::SignerCapabilities;

    /// Creates a signature.
    ///
    /// `issuer` is an identifier for requests through the signature API,
    /// or a key for self-signed outputs created internally. Implementations
    /// add the signature to their revocation method, if any, and return
    /// its ID with the result: the same ID is used to revoke the signature
    /// and to check its status.
    async fn sign(
        &self,
        issuer: Issuer,
        request: dto::CreateSignatureRequest,
    ) -> Result<dto::CreateSignatureResponseDTO, SignerError>;

    /// The revocation method for this signer's signatures. `None` means
    /// its signatures cannot be revoked.
    fn revocation_method(&self) -> Result<Option<Arc<dyn RevocationMethod>>, SignerError>;

    /// The key of this signer's entry in the `signer` configuration.
    /// Stored with each signature on the revocation list, and returned
    /// as the signature's `type` by the revocation check.
    fn config_name(&self) -> &SignerId;
}

impl Display for dyn Signer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer `{}`", self.config_name())
    }
}
