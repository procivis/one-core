use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use error::FormatterError;
use model::{AuthenticationFn, CredentialPresentation, DetailCredential, TokenVerifier};
use proc_macros::provider_mock;
use shared_types::{
    CredentialFormat, CredentialSchemaId, OrganisationId, RevocationMethodId, SerializedCredential,
};
use time::Duration;

use crate::config::core_config::{KeyAlgorithmType, RevocationType};
use crate::model::credential_schema::CredentialSchema;
use crate::model::organisation::Organisation;
use crate::provider::Provider;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::util::key_selection::SelectedKey;

pub(crate) mod common;

mod decorators;
pub mod error;
mod json_claims;
pub mod json_ld_bbsplus;
pub mod json_ld_classic;
pub mod jwt_formatter;
pub mod mapper;
pub mod mdoc_formatter;
pub mod model;
pub mod provider;
pub mod sdjwt;
pub mod sdjwt_formatter;
pub mod sdjwtvc_formatter;
pub mod status_list_jwt_formatter;
pub mod vcdm;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataClaimSchema {
    pub key: String,
    pub data_type: String,
    pub array: bool,
    pub required: bool,
}

/// Format credentials for sharing and parse credentials which have been shared.
#[expect(clippy::too_many_arguments)]
#[provider_mock]
#[async_trait]
pub trait CredentialFormatter: Provider + Send + Sync {
    /// Formats and signs a credential.
    async fn format_credential(
        &self,
        credential_data: model::CredentialData,
        auth_fn: model::AuthenticationFn,
    ) -> Result<SerializedCredential, error::FormatterError>;

    /// Formats Status List credential
    async fn format_status_list<'a>(
        &self,
        revocation_list_url: String,
        issuer: SelectedKey,
        encoded_list: String,
        algorithm: KeyAlgorithmType,
        auth_fn: AuthenticationFn,
        status_purpose: StatusPurpose,
        status_list_type: RevocationType,
    ) -> Result<Vec<u8>, FormatterError>;

    /// Parses a received credential and verifies the signature.
    async fn extract_credentials<'a>(
        &self,
        credentials: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<DetailCredential, FormatterError>;

    /// Parses a received credential without verifying the signature.
    async fn extract_credentials_unverified<'a>(
        &self,
        credential: &SerializedCredential,
        credential_schema: Option<&'a CredentialSchema>,
    ) -> Result<DetailCredential, FormatterError>;

    /// Formats presentation with selective disclosure.
    ///
    /// For those formats capable of selective disclosure, call this with the keys of the claims
    /// to be shared. The token is processed and returns the correctly formatted presentation
    /// containing only the selected attributes.
    async fn prepare_selective_disclosure(
        &self,
        credential: CredentialPresentation,
    ) -> Result<String, FormatterError>;

    /// Returns the leeway time.
    ///
    /// Leeway is a buffer time added to account for clock skew
    /// between systems when validating issuance and expiration dates of presentations
    /// and the credentials included therein. This prevents minor discrepancies in system
    /// clocks from causing validation failures.
    fn get_leeway(&self) -> Duration;

    /// Returns this format's default credential validity duration, used when no
    /// business-level expiration is configured on the credential schema.
    fn get_default_expiration(&self) -> Duration;

    /// See the [API docs][cfc] for a complete list of credential format capabilities.
    ///
    /// [cfc]: https://docs.procivis.ch/api/resources/credential_schemas#credential-format-capabilities
    fn get_capabilities(&self) -> model::FormatterCapabilities;

    /// Returns the schema id to be used for a newly created schema.
    /// It may be derived from the `id`, the creation request and the `core_base_url`.
    fn credential_schema_id<'a>(
        &self,
        id: CredentialSchemaId,
        _organisation_id: OrganisationId,
        _ecosystem_schema_id: Option<&'a str>,
        core_base_url: &'a str,
        format: &CredentialFormat,
    ) -> Result<String, FormatterError> {
        Ok(format!("{core_base_url}/ssi/schema/v2/{id}/{format}"))
    }

    /// Returns definitions of metadata claims for the format
    fn get_metadata_claims(&self) -> Vec<MetadataClaimSchema>;

    /// Path to the subtree of user (non-metadata) claims within the formatted credentials
    ///
    /// Returns path segments
    /// Returns empty if user claims do not appear nested in any specific metadata claim
    fn user_claims_path(&self) -> Vec<String>;

    /// Parse issued credential on holder side.
    /// Reconstructs credential_schema, claims, issuer identifiers etc.
    async fn parse_credential(
        &self,
        credential: &SerializedCredential,
        organisation: Organisation,
        verification: Box<dyn TokenVerifier>,
    ) -> Result<model::ParsedCredential, FormatterError>;

    #[expect(clippy::needless_lifetimes)]
    fn revocation_method_id<'a>(&'a self) -> Option<&'a RevocationMethodId>;

    fn config_name(&self) -> &CredentialFormat;
}

impl Display for dyn CredentialFormatter {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credential format `{}`", self.config_name())
    }
}
