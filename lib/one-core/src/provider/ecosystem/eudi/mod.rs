use std::sync::Arc;

use async_trait::async_trait;
use holder_issuance::HolderIssuanceResolver;
use holder_proof::HolderProofResolver;
use proc_macros::Provider;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::i18n::I18nString;
use shared_types::{CredentialFormat, CredentialId, EcosystemId, OrganisationId, ProofId};
use standardized_types::openid4vp::dcql::CredentialQueryId;
use time::Duration;

use super::Ecosystem;
use super::error::EcosystemError;
use super::model::{
    EcosystemCapabilities, EcosystemRole, ProtocolArtifact, SchemaFilter, TrustDetail,
};
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierFilterValue;
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::proto::session_provider::SessionProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::model::TrustScope;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

mod holder_issuance;
mod holder_proof;
mod identifier_filter;
mod mapper;
mod trust_detail;
mod validator;
mod verifier_submission;

#[serde_as]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    #[serde(default)]
    pub credential_schemas: Vec<CredentialSchemaParams>,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_1_minute")]
    pub leeway_seconds: Duration,
}

fn default_1_minute() -> Duration {
    Duration::minutes(1)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaParams {
    pub format: CredentialFormat,
    pub pid_schema_ids: Vec<String>,
}

#[derive(Provider)]
pub struct EudiEcosystem {
    config_id: EcosystemId,
    params: Params,
    config: CoreConfig,

    holder_proof_resolver: HolderProofResolver,
    holder_issuance_resolver: HolderIssuanceResolver,
    wrp_validator: Arc<dyn WRPValidator>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
}

impl EudiEcosystem {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: EcosystemId,
        params: serde_json::Value,
        config: CoreConfig,
        history_repository: Arc<dyn HistoryRepository>,
        interaction_repository: Arc<dyn InteractionRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config,
            holder_proof_resolver: HolderProofResolver::new(
                history_repository.clone(),
                wrp_validator.clone(),
                blob_storage_provider.clone(),
                session_provider.clone(),
                config_id.clone(),
            ),
            holder_issuance_resolver: HolderIssuanceResolver::new(
                history_repository.clone(),
                interaction_repository,
                wrp_validator.clone(),
                blob_storage_provider.clone(),
                session_provider,
                formatter_provider.clone(),
                params.leeway_seconds,
                config_id.clone(),
            ),
            config_id,
            wrp_validator,
            formatter_provider,
            credential_schema_repository,
            proof_schema_repository,
            history_repository,
            blob_storage_provider,
            params,
        })
    }

    /// Trust may only be resolved against collections of the ecosystem being acted in.
    pub(super) fn trust_scope(&self, organisation_id: OrganisationId) -> TrustScope {
        TrustScope {
            organisation_id,
            ecosystem: self.config_id.to_owned(),
        }
    }
}

#[async_trait]
impl Ecosystem for EudiEcosystem {
    fn config_name(&self) -> &EcosystemId {
        &self.config_id
    }

    fn get_capabilities(&self) -> EcosystemCapabilities {
        EcosystemCapabilities {
            ecosystem_roles: vec![
                EcosystemRole::Holder,
                EcosystemRole::Issuer,
                EcosystemRole::Verifier,
                EcosystemRole::PidProvider,
                EcosystemRole::NationalRegistryRegistrar,
                EcosystemRole::WalletProvider,
            ],
        }
    }

    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    async fn validate_interaction<'a>(
        &self,
        interaction_artifact: &ProtocolArtifact<'a>,
        interaction: &Interaction,
    ) -> Result<(), EcosystemError> {
        match interaction_artifact {
            ProtocolArtifact::HolderIssuanceInvitation {
                issuer_metadata,
                credential_configuration_ids,
            } => {
                self.holder_issuance_resolver
                    .resolve_metadata_trust(
                        interaction,
                        issuer_metadata,
                        credential_configuration_ids,
                    )
                    .await
                    .error_while("resolving holder issuance trust")?;
            }
            ProtocolArtifact::HolderIssuanceCredential {
                credential,
                serialized,
                credential_configuration_id,
            } => {
                self.holder_issuance_resolver
                    .resolve_credential_issuer_trust(
                        credential,
                        serialized,
                        credential_configuration_id,
                        interaction,
                    )
                    .await
                    .error_while("resolving holder issuance trust")?;
            }
            ProtocolArtifact::HolderProof {
                verifier_details,
                dcql_query,
                verifier_info,
                proof_id,
            } => {
                self.holder_proof_resolver
                    .resolve_trust(
                        verifier_details.as_ref().as_ref(),
                        *proof_id,
                        interaction.organisation.id(),
                        dcql_query,
                        verifier_info,
                        self.params.leeway_seconds,
                    )
                    .await
                    .error_while("resolving holder proof trust")?;
            }
            ProtocolArtifact::IssuerIssuance { wallet_provider } => {
                self.wrp_validator
                    .validate_wallet_provider(
                        wallet_provider.to_owned(),
                        &self.trust_scope(interaction.organisation.id()),
                    )
                    .await
                    .error_while("validating wallet provider")?
                    .ok_or(EcosystemError::UntrustedIdentifier)?;
            }
            ProtocolArtifact::VerifierSubmission {
                credential,
                issuer_details,
            } => {
                self.resolve_verifier_submission(
                    credential,
                    issuer_details,
                    interaction.organisation.id(),
                )
                .await?;
            }
        };

        Ok(())
    }

    async fn validate_credential(&self, credential: &Credential) -> Result<(), EcosystemError> {
        self.validate_credential_creation(credential).await
    }

    async fn validate_proof(&self, proof: &Proof) -> Result<(), EcosystemError> {
        self.validate_proof_creation(proof).await
    }

    async fn identifier_filter<'a>(
        &self,
        role: EcosystemRole,
        schema: Option<&'a SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        self.get_filter(role, schema).await
    }

    async fn issuer_trust_details(
        &self,
        credential_id: &CredentialId,
    ) -> Result<TrustDetail, EcosystemError> {
        self.get_trust_detail((*credential_id).into()).await
    }

    async fn verifier_trust_details(
        &self,
        proof_id: &ProofId,
    ) -> Result<TrustDetail, EcosystemError> {
        self.get_trust_detail((*proof_id).into()).await
    }

    async fn get_trust_purpose(
        &self,
        proof_id: &ProofId,
        query_id: &CredentialQueryId,
    ) -> Result<Option<I18nString>, EcosystemError> {
        self.trust_purpose((*proof_id).into(), query_id).await
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        todo!()
    }
}
