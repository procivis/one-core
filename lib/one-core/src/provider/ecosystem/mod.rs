#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use proc_macros::provider_mock;
use shared_types::EcosystemId;

use crate::model::credential::Credential;
use crate::model::identifier::IdentifierFilterValue;
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::provider::Provider;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{
    EcosystemCapabilities, EcosystemRole, IssuerTrustDetails, ProtocolArtifact, SchemaFilter,
    VerifierTrustDetails,
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

    async fn validate_interaction<'a>(
        &self,
        interaction_artifact: &ProtocolArtifact<'a>,
        interaction: &Interaction,
    ) -> Result<(), EcosystemError>;

    /// validate credential before issuance (issuer)
    async fn validate_credential(&self, credential: &Credential) -> Result<(), EcosystemError>;
    /// validate proof before request (verifier)
    async fn validate_proof(&self, proof: &Proof) -> Result<(), EcosystemError>;

    async fn identifier_filter<'a>(
        &self,
        role: EcosystemRole,
        schema: Option<&'a SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError>;

    fn issuer_trust_details(
        &self,
        credential: &Credential,
    ) -> Result<IssuerTrustDetails, EcosystemError>;

    fn verifier_trust_details(
        &self,
        credential: &Credential,
    ) -> Result<VerifierTrustDetails, EcosystemError>;

    fn lifecycle_hook(&self) -> Result<(), EcosystemError>;
}

impl Display for dyn Ecosystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ecosystem `{}`", self.config_name())
    }
}
