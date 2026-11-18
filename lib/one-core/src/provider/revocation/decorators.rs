use std::fmt::Display;
use std::sync::Arc;

use shared_types::{RevocationListEntryId, RevocationListId, RevocationMethodId, SignerId};

use super::RevocationMethod;
use super::error::RevocationError;
use super::model::{
    CredentialRevocationInfo, ReservedEntries, RevocationMethodCapabilities, RevocationState,
};
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::identifier::Identifier;
use crate::model::managed_instance_attestation::ManagedInstanceAttestation;
use crate::model::revocation_list::UpdateRevocationListEntryId;
use crate::provider::Provider;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::disabled_provider::DisabledProvider;
use crate::provider::provider_directory::WithDisabledDecorator;
use crate::provider::revocation::model::Operation;

impl WithDisabledDecorator for dyn RevocationMethod {
    fn decorate(self: Arc<dyn RevocationMethod>) -> Arc<dyn RevocationMethod> {
        Arc::new(DisabledProvider::new(self))
    }
}

#[async_trait::async_trait]
impl<T: Provider + RevocationMethod + Display + ?Sized> RevocationMethod for DisabledProvider<T> {
    fn can_check_status(&self, credential_status: &CredentialStatus) -> bool {
        self.inner().can_check_status(credential_status)
    }

    async fn reserve_credential_entries(
        &self,
        _credential: &Credential,
    ) -> Result<ReservedEntries, RevocationError> {
        self.disabled_error()
    }

    async fn set_entries_state(
        &self,
        entries: Vec<UpdateRevocationListEntryId>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        self.inner().set_entries_state(entries, new_state).await
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        self.inner()
            .check_credential_revocation_status(credential_status, issuer_details, force_refresh)
            .await
    }

    async fn add_issued_attestation(
        &self,
        _attestation: &ManagedInstanceAttestation,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        self.disabled_error()
    }

    async fn add_signature<'a>(
        &self,
        _signature_type: SignerId,
        _issuer: &'a Identifier,
        _certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        self.disabled_error()
    }

    async fn get_updated_list(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<u8>, RevocationError> {
        self.inner().get_updated_list(list_id).await
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        self.inner().get_capabilities()
    }

    fn config_name(&self) -> &RevocationMethodId {
        self.inner().config_name()
    }
}

/// Checks supported operations
pub(super) struct CapabilityChecked(pub Arc<dyn RevocationMethod>);

impl Provider for CapabilityChecked {
    fn capabilities(&self) -> Option<serde_json::Value> {
        self.0.capabilities()
    }
}

impl CapabilityChecked {
    fn check_revocation_state_eligibility(
        &self,
        state: &RevocationState,
    ) -> Result<(), RevocationError> {
        let operation = match state {
            RevocationState::Valid => return Ok(()),
            RevocationState::Revoked => Operation::Revoke,
            RevocationState::Suspended { .. } => Operation::Suspend,
        };

        if !self.0.get_capabilities().operations.contains(&operation) {
            return Err(RevocationError::OperationNotSupported(
                operation.to_string(),
            ));
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl RevocationMethod for CapabilityChecked {
    fn can_check_status(&self, credential_status: &CredentialStatus) -> bool {
        self.0.can_check_status(credential_status)
    }

    async fn reserve_credential_entries(
        &self,
        credential: &Credential,
    ) -> Result<ReservedEntries, RevocationError> {
        self.0.reserve_credential_entries(credential).await
    }

    async fn set_entries_state(
        &self,
        entries: Vec<UpdateRevocationListEntryId>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        self.check_revocation_state_eligibility(&new_state)?;
        self.0.set_entries_state(entries, new_state).await
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        self.0
            .check_credential_revocation_status(credential_status, issuer_details, force_refresh)
            .await
    }

    async fn add_issued_attestation(
        &self,
        attestation: &ManagedInstanceAttestation,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        self.0.add_issued_attestation(attestation).await
    }

    async fn add_signature<'a>(
        &self,
        signature_type: SignerId,
        issuer: &'a Identifier,
        certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        self.0
            .add_signature(signature_type, issuer, certificate)
            .await
    }

    async fn get_updated_list(
        &self,
        list_id: RevocationListId,
    ) -> Result<Vec<u8>, RevocationError> {
        self.0.get_updated_list(list_id).await
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        self.0.get_capabilities()
    }

    fn config_name(&self) -> &RevocationMethodId {
        self.0.config_name()
    }
}
