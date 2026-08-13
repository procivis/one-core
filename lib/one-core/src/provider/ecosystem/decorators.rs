use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::EcosystemId;

use super::Ecosystem;
use super::error::EcosystemError;
use super::model::{
    EcosystemCapabilities, EcosystemRole, IssuerTrustDetails, ProtocolArtifact, SchemaFilter,
    VerifierTrustDetails,
};
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierFilterValue;
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;

impl WithDisabledDecorator for dyn Ecosystem {
    fn decorate(self: Arc<dyn Ecosystem>) -> Arc<dyn Ecosystem> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait]
impl<T: Ecosystem + Display + ?Sized> Ecosystem for DisabledProvider<T> {
    fn config_name(&self) -> &EcosystemId {
        self.inner().config_name()
    }

    fn get_capabilities(&self) -> EcosystemCapabilities {
        self.inner().get_capabilities()
    }

    async fn validate_interaction<'a>(
        &self,
        _interaction_artifact: &ProtocolArtifact<'a>,
        _interaction: &Interaction,
    ) -> Result<(), EcosystemError> {
        self.disabled_error()
    }

    async fn validate_credential(&self, _credential: &Credential) -> Result<(), EcosystemError> {
        self.disabled_error()
    }
    async fn validate_proof(&self, _proof: &Proof) -> Result<(), EcosystemError> {
        self.disabled_error()
    }

    async fn identifier_filter<'a>(
        &self,
        _role: EcosystemRole,
        _schema: Option<&'a SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        self.disabled_error()
    }

    fn issuer_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<IssuerTrustDetails, EcosystemError> {
        self.disabled_error()
    }

    fn verifier_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<VerifierTrustDetails, EcosystemError> {
        self.disabled_error()
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        self.disabled_error()
    }
}
