use std::sync::Arc;

use async_trait::async_trait;
use holder_issuance::HolderIssuanceResolver;
use holder_proof::HolderProofResolver;
use mapper::credential_schema_to_schema_format;
use proc_macros::Provider;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{CredentialFormat, EcosystemId};
use time::Duration;

use super::Ecosystem;
use super::error::EcosystemError;
use super::model::{
    EcosystemCapabilities, EcosystemRole, IssuerTrustDetails, ProtocolArtifact, SchemaFilter,
    VerifierTrustDetails,
};
use crate::config::core_config::CoreConfig;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::identifier::{IdentifierData, IdentifierFilterValue};
use crate::model::interaction::Interaction;
use crate::model::list_filter::ListFilterCondition;
use crate::model::proof::Proof;
use crate::proto::session_provider::SessionProvider;
use crate::proto::wrp_validator::WRPValidator;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;

mod holder_issuance;
mod holder_proof;
mod mapper;
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
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            config,
            holder_proof_resolver: HolderProofResolver::new(
                history_repository.clone(),
                wrp_validator.clone(),
                blob_storage_provider.clone(),
                session_provider.clone(),
            ),
            holder_issuance_resolver: HolderIssuanceResolver::new(
                history_repository,
                interaction_repository,
                wrp_validator.clone(),
                blob_storage_provider,
                session_provider,
                formatter_provider.clone(),
                params.leeway_seconds,
            ),
            wrp_validator,
            formatter_provider,
            params,
        })
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
                        interaction.organisation.id(),
                    )
                    .await
                    .error_while("validating wallet provider")?;
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
        let Some(issuer_identifier) = &credential.issuer_identifier else {
            return Err(EcosystemError::MissingIdentifier);
        };
        let issuer_identifier = issuer_identifier.as_ref().await?;

        if !matches!(issuer_identifier.data, IdentifierData::Certificate(_)) {
            return Err(EcosystemError::InvalidIdentifier(issuer_identifier.id));
        }

        let Some(_issuer_certificate) = &credential.issuer_certificate else {
            return Err(EcosystemError::MissingIdentifier);
        };

        let reg_certs = issuer_identifier.trust_information.as_ref().await?;
        if !reg_certs.is_empty() {
            let credential_schema = credential.schema.as_ref().await?;
            let schema_format =
                credential_schema_to_schema_format(&credential_schema, &self.config).await?;

            if !reg_certs
                .iter()
                .any(|reg_cert| reg_cert.allowed_issuance_types.contains(&schema_format))
            {
                return Err(EcosystemError::DisallowedSchemaFormat(schema_format));
            }
        }

        Ok(())
    }

    async fn validate_proof(&self, proof: &Proof) -> Result<(), EcosystemError> {
        let Some(verifier_identifier) = &proof.verifier_identifier else {
            return Err(EcosystemError::MissingIdentifier);
        };

        if !matches!(verifier_identifier.data, IdentifierData::Certificate(_)) {
            return Err(EcosystemError::InvalidIdentifier(verifier_identifier.id));
        }

        let Some(_verifier_certificate) = &proof.verifier_certificate else {
            return Err(EcosystemError::MissingIdentifier);
        };

        let reg_certs = verifier_identifier.trust_information.as_ref().await?;
        if !reg_certs.is_empty() {
            let Some(proof_schema) = &proof.schema else {
                return Err(EcosystemError::MappingError(
                    "Missing proof schema".to_string(),
                ));
            };

            let input_schemas = proof_schema.input_schemas.as_ref().await?;
            for input_schema in &input_schemas {
                let credential_schema = input_schema.credential_schema.as_ref().await?;
                let schema_format =
                    credential_schema_to_schema_format(&credential_schema, &self.config).await?;

                if !reg_certs
                    .iter()
                    .any(|reg_cert| reg_cert.allowed_verification_types.contains(&schema_format))
                {
                    return Err(EcosystemError::DisallowedSchemaFormat(schema_format));
                }
            }
        }

        Ok(())
    }

    fn identifier_filter(
        &self,
        _role: EcosystemRole,
        _schema: Option<SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        todo!()
    }

    fn issuer_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<IssuerTrustDetails, EcosystemError> {
        todo!()
    }

    fn verifier_trust_details(
        &self,
        _credential: &Credential,
    ) -> Result<VerifierTrustDetails, EcosystemError> {
        todo!()
    }

    fn lifecycle_hook(&self) -> Result<(), EcosystemError> {
        todo!()
    }
}
