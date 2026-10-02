use std::sync::Arc;

use async_trait::async_trait;
use proc_macros::Provider;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::i18n::I18nString;
use shared_types::{
    CredentialFormat, CredentialId, EcosystemId, IdentifierTrustInformationId, OrganisationId,
    ProofId,
};
use standardized_types::openid4vp::dcql::CredentialQueryId;
use time::Duration;

use super::Ecosystem;
use super::error::EcosystemError;
use super::model::{
    EcosystemCapabilities, EcosystemRole, ParsedTrustInformation, ProtocolArtifact, SchemaFilter,
    TrustDetail, TrustInformationInput,
};
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::identifier::{Identifier, IdentifierFilterValue};
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::proto::credential_validity_manager::CredentialValidityManager;
use crate::proto::session_provider::SessionProvider;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::model::TrustScope;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::proof_schema_repository::ProofSchemaRepository;

mod holder_issuance;
mod holder_proof;
mod identifier_filter;
mod issuer_issuance;
mod lifecycle;
mod mapper;
mod trust_detail;
mod trust_information;
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

/// The schema ids this ecosystem considers a PID for the given credential format.
pub(super) fn pid_schema_ids(
    credential_schemas: &[CredentialSchemaParams],
    format: &CredentialFormat,
) -> Vec<String> {
    credential_schemas
        .iter()
        .filter(|schema| &schema.format == format)
        .flat_map(|schema| schema.pid_schema_ids.iter().cloned())
        .collect()
}

/// A registration certificate or a national registry entry. Both list the allowed credentials.
#[derive(Debug, Clone, Copy, strum::Display)]
pub(crate) enum AttestationCoverageSource {
    #[strum(serialize = "registration certificate")]
    RegistrationCertificate,
    #[strum(serialize = "national registry response")]
    NationalRegistry,
}

#[derive(Provider)]
pub struct EudiEcosystem {
    config_id: EcosystemId,
    params: Params,
    config: CoreConfig,

    wrp_validator: Arc<dyn WRPValidator>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    credential_repository: Arc<dyn CredentialRepository>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository>,
    history_repository: Arc<dyn HistoryRepository>,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    session_provider: Arc<dyn SessionProvider>,
    wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
    credential_validity_manager: Arc<dyn CredentialValidityManager>,
}

impl EudiEcosystem {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: EcosystemId,
        params: serde_json::Value,
        config: CoreConfig,
        history_repository: Arc<dyn HistoryRepository>,
        wrp_validator: Arc<dyn WRPValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        session_provider: Arc<dyn SessionProvider>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        credential_repository: Arc<dyn CredentialRepository>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        proof_schema_repository: Arc<dyn ProofSchemaRepository>,
        wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        credential_validity_manager: Arc<dyn CredentialValidityManager>,
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config,
            config_id,
            wrp_validator,
            formatter_provider,
            credential_repository,
            credential_schema_repository,
            proof_schema_repository,
            history_repository,
            blob_storage_provider,
            session_provider,
            wallet_unit_proto,
            credential_validity_manager,
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

    #[tracing::instrument(
        level = "debug",
        skip_all,
        fields(ecosystem = %self.config_id),
        err(level = "debug")
    )]
    async fn validate_interaction<'a>(
        &self,
        interaction_artifact: &ProtocolArtifact<'a>,
        interaction: &Interaction,
    ) -> Result<Option<serde_json::Value>, EcosystemError> {
        match interaction_artifact {
            ProtocolArtifact::HolderIssuanceInvitation {
                issuer_metadata,
                credential_configuration_ids,
            } => {
                let data = self
                    .resolve_metadata_trust(
                        interaction.organisation.id(),
                        issuer_metadata,
                        credential_configuration_ids,
                    )
                    .await
                    .error_while("resolving holder issuance trust")?;
                return Ok(Some(data));
            }
            ProtocolArtifact::HolderIssuanceCredential {
                credential,
                serialized,
                credential_configuration_id,
            } => {
                self.resolve_credential_issuer_trust(
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
                self.resolve_holder_proof(
                    verifier_details.as_ref().as_ref(),
                    *proof_id,
                    interaction.organisation.id(),
                    dcql_query,
                    verifier_info,
                )
                .await
                .error_while("resolving holder proof trust")?;
            }
            ProtocolArtifact::IssuerIssuance {
                attestation,
                requirements,
                ..
            } => {
                self.resolve_wallet_attestation(
                    attestation,
                    requirements,
                    interaction.organisation.id(),
                )
                .await?;
            }
            ProtocolArtifact::VerifierSubmission {
                credential,
                issuer_details,
                ..
            } => {
                self.resolve_verifier_submission(
                    credential,
                    issuer_details,
                    interaction.organisation.id(),
                )
                .await?;
            }
        };

        Ok(None)
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

    async fn lifecycle_hook(&self) -> Result<serde_json::Value, EcosystemError> {
        self.run_lifecycle_check().await
    }

    async fn parse_identifier_trust_information(
        &self,
        identifier: &Identifier,
        trust_information: &[TrustInformationInput],
    ) -> Result<Vec<ParsedTrustInformation>, EcosystemError> {
        self.parse_trust_information(identifier, trust_information)
            .await
    }

    async fn orphaned_identifier_trust_information(
        &self,
        identifier: &Identifier,
    ) -> Result<Vec<IdentifierTrustInformationId>, EcosystemError> {
        self.find_orphaned_trust_information(identifier).await
    }
}
