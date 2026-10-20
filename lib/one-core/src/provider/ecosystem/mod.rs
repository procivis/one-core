use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::i18n::I18nString;
use shared_types::{CredentialId, EcosystemId, IdentifierTrustInformationId, ProofId};
use standardized_types::openid4vp::dcql::CredentialQueryId;

use crate::model::credential::Credential;
use crate::model::identifier::{Identifier, IdentifierFilterValue};
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::provider::Provider;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{
    EcosystemCapabilities, EcosystemRole, EcosystemValidationResult, ParsedTrustInformation,
    ProtocolArtifact, SchemaFilter, TrustDetail, TrustInformationInput,
};

pub(crate) mod decorators;
pub(crate) mod directory;
pub mod error;
pub mod model;

pub(crate) mod eudi;

#[provider_mock]
#[async_trait]
pub trait Ecosystem: Provider + Send + Sync {
    fn config_name(&self) -> &EcosystemId;

    fn get_capabilities(&self) -> EcosystemCapabilities;

    /// Returns the verdict and optional data for later steps. The resolver stores both on
    /// the interaction.
    async fn validate_interaction<'a>(
        &self,
        interaction_artifact: &ProtocolArtifact<'a>,
        interaction: &Interaction,
    ) -> Result<EcosystemValidationResult, EcosystemError>;

    /// validate credential before issuance (issuer)
    async fn validate_credential(&self, credential: &Credential) -> Result<(), EcosystemError>;
    /// validate proof before request (verifier)
    async fn validate_proof(&self, proof: &Proof) -> Result<(), EcosystemError>;

    async fn identifier_filter<'a>(
        &self,
        role: EcosystemRole,
        schema: Option<&'a SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError>;

    async fn issuer_trust_details(
        &self,
        credential_id: &CredentialId,
    ) -> Result<TrustDetail, EcosystemError>;

    async fn verifier_trust_details(
        &self,
        proof_id: &ProofId,
    ) -> Result<TrustDetail, EcosystemError>;

    async fn get_trust_purpose(
        &self,
        proof_id: &ProofId,
        query_id: &CredentialQueryId,
    ) -> Result<Option<I18nString>, EcosystemError>;

    /// Returns the technical key paths of all claims that require explicit / biometric user consent
    fn get_biometric_consent_claims(&self, ecosystem_schema_id: &str) -> Vec<String>;

    async fn lifecycle_hook(&self) -> Result<serde_json::Value, EcosystemError>;

    /// Validates uploaded trust information against the identifier's access certificates.
    /// Returns `Err(EcosystemError::NotApplicable)` when this ecosystem does not handle the
    /// given trust information type(s), so the caller can try the next candidate ecosystem.
    async fn parse_identifier_trust_information(
        &self,
        identifier: &Identifier,
        trust_information: &[TrustInformationInput],
    ) -> Result<Vec<ParsedTrustInformation>, EcosystemError>;

    async fn orphaned_identifier_trust_information(
        &self,
        identifier: &Identifier,
    ) -> Result<Vec<IdentifierTrustInformationId>, EcosystemError>;
}

impl Display for dyn Ecosystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ecosystem `{}`", self.config_name())
    }
}
