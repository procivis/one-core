use async_trait::async_trait;
use error::FormatterError;
use model::{AuthenticationFn, CredentialPresentation, DetailCredential, TokenVerifier};
use shared_types::CredentialSchemaId;

use crate::model::revocation_list::StatusListType;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::service::credential_schema::dto::CreateCredentialSchemaRequestDTO;

pub mod error;

pub(crate) mod common;
pub use common::nest_claims;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::credential_schema::CredentialSchema;
use crate::model::identifier::Identifier;
use crate::provider::credential_formatter::model::HolderBindingCtx;

// Implementation
pub mod json_ld_bbsplus;
pub mod json_ld_classic;
pub mod jwt_formatter;
pub mod mapper;
pub mod mdoc_formatter;
pub mod model;
pub mod physical_card;
pub mod provider;
pub mod sdjwt;
pub mod sdjwt_formatter;
pub mod sdjwtvc_formatter;
pub mod status_list_jwt_formatter;
pub mod vcdm;

#[cfg(test)]
mod test;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataClaimSchema {
    pub key: String,
    pub data_type: String,
    pub array: bool,
    pub required: bool,
}

/// Format credentials for sharing and parse credentials which have been shared.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait]
pub trait CredentialFormatter: Send + Sync {
    /// Formats and signs a credential.
    async fn format_credential<'a>(
        &self,
        credential_data: model::CredentialData,
        auth_fn: model::AuthenticationFn,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<String, error::FormatterError>;

    /// Formats BitStringStatusList credential
    async fn format_status_list(
        &self,
        revocation_list_url: String,
        issuer_identifier: &Identifier,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: StatusListType,
    ) -> Result<String, FormatterError>;

    /// Parses a received credential and verifies the signature.
    async fn extract_credentials<'a>(
        &self,
        credentials: &str,
        credential_schema: Option<&'a CredentialSchema>,
        verification: Box<dyn TokenVerifier>,
        holder_binding_ctx: Option<HolderBindingCtx>,
    ) -> Result<DetailCredential, FormatterError>;

    /// Parses a received credential without verifying the signature.
    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &str,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError>;

    /// Formats presentation with selective disclosure.
    ///
    /// For those formats capable of selective disclosure, call this with the keys of the claims
    /// to be shared. The token is processed and returns the correctly formatted presentation
    /// containing only the selected attributes.
    async fn format_credential_presentation(
        &self,
        credential: CredentialPresentation,
        holder_binding_ctx: Option<HolderBindingCtx>,
        holder_binding_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError>;

    /// Returns the leeway time.
    ///
    /// Leeway is a buffer time (in seconds) added to account for clock skew
    /// between systems when validating issuance and expiration dates of presentations
    /// and the credentials included therein. This prevents minor discrepancies in system
    /// clocks from causing validation failures.
    fn get_leeway(&self) -> u64;

    /// See the [API docs][cfc] for a complete list of credential format capabilities.
    ///
    /// [cfc]: https://docs.procivis.ch/api/resources/credential_schemas#credential-format-capabilities
    fn get_capabilities(&self) -> model::FormatterCapabilities;

    /// Returns the schema id to be used for a newly created schema.
    /// It may be derived from the `id`, the creation request and the `core_base_url`.
    fn credential_schema_id(
        &self,
        id: CredentialSchemaId,
        _request: &CreateCredentialSchemaRequestDTO,
        core_base_url: &str,
    ) -> Result<String, FormatterError> {
        Ok(format!("{core_base_url}/ssi/schema/v1/{id}"))
    }

    /// Returns definitions of metadata claims for the format
    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema>;

    /// Path to the subtree of user (non-metadata) claims within the formatted credentials
    ///
    /// Returns path segments
    /// Returns empty if user claims do not appear nested in any specific metadata claim
    fn user_claims_path(&self) -> Vec<String>;
}
