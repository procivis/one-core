use std::fmt::Display;
use std::sync::Arc;

use async_trait::async_trait;
use shared_types::{CredentialId, EcosystemId, ProofId};

use super::Ecosystem;
use super::error::EcosystemError;
use super::model::{
    EcosystemCapabilities, EcosystemRole, ProtocolArtifact, SchemaFilter, TrustDetail,
};
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierFilterValue;
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::provider::Provider;
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

    async fn issuer_trust_details(
        &self,
        _credential_id: &CredentialId,
    ) -> Result<TrustDetail, EcosystemError> {
        self.disabled_error()
    }

    async fn verifier_trust_details(
        &self,
        _proof_id: &ProofId,
    ) -> Result<TrustDetail, EcosystemError> {
        self.disabled_error()
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        self.disabled_error()
    }
}

/// Checks supported operations
pub(super) struct CapabilityChecked(pub Arc<dyn Ecosystem>);

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

#[async_trait::async_trait]
impl Ecosystem for CapabilityChecked {
    fn config_name(&self) -> &EcosystemId {
        self.0.config_name()
    }

    fn get_capabilities(&self) -> EcosystemCapabilities {
        self.0.get_capabilities()
    }

    async fn validate_interaction<'a>(
        &self,
        interaction_artifact: &ProtocolArtifact<'a>,
        interaction: &Interaction,
    ) -> Result<(), EcosystemError> {
        self.0
            .validate_interaction(interaction_artifact, interaction)
            .await
    }

    async fn validate_credential(&self, credential: &Credential) -> Result<(), EcosystemError> {
        self.0.validate_credential(credential).await
    }
    async fn validate_proof(&self, proof: &Proof) -> Result<(), EcosystemError> {
        self.0.validate_proof(proof).await
    }

    async fn identifier_filter<'a>(
        &self,
        role: EcosystemRole,
        schema: Option<&'a SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        if !self.0.get_capabilities().ecosystem_roles.contains(&role) {
            return Err(EcosystemError::UnsupportedRole(role));
        }

        self.0.identifier_filter(role, schema).await
    }

    async fn issuer_trust_details(
        &self,
        credential_id: &CredentialId,
    ) -> Result<TrustDetail, EcosystemError> {
        self.0.issuer_trust_details(credential_id).await
    }

    async fn verifier_trust_details(
        &self,
        proof_id: &ProofId,
    ) -> Result<TrustDetail, EcosystemError> {
        self.0.verifier_trust_details(proof_id).await
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        self.0.lifecycle_hook()
    }
}
