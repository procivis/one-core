use shared_types::{CredentialId, OrganisationId, SerializedCredential};
use uuid::Uuid;

use super::metadata::MetadataEcosystemData;
use super::{HolderIssuanceError, HolderIssuanceResolver};
use crate::clock::now_utc;
use crate::config::core_config::BlobStorageType;
use crate::error::ContextWithErrorCode;
use crate::model::blob::{Blob, BlobType};
use crate::model::credential::Credential;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryMetadata, HistorySource,
    WalletRelyingPartyMetadata,
};
use crate::model::interaction::Interaction;
use crate::proto::session_provider::SessionExt;
use crate::proto::wrp_validator::credential_category;
use crate::provider::credential_formatter::model::{IdentifierDetails, X5References};
use crate::provider::ecosystem::eudi::mapper::formatter_requires_namespaces;

impl HolderIssuanceResolver {
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(crate) async fn resolve_credential_issuer_trust(
        &self,
        credential: &Credential,
        serialized: &SerializedCredential,
        credential_configuration_id: &String,
        interaction: &Interaction,
    ) -> Result<(), HolderIssuanceError> {
        let schema = credential.schema.as_ref().await?;
        let format = schema.format().await?;
        let formatter = self.formatter_provider.get_credential_formatter(&format)?;
        let organisation_id = interaction.organisation.id();

        let issuer = formatter
            .extract_credentials_unverified(serialized, Some(&schema))
            .await
            .error_while("parsing credential")?
            .issuer;

        let claims = credential.claims.as_ref().await?;
        let credential_category = {
            let namespaced = formatter_requires_namespaces(formatter.as_ref());
            credential_category(&claims, namespaced)
        };

        let (chain, x5_references) = match &issuer {
            IdentifierDetails::Certificate(certificate) => {
                (Some(certificate.chain.as_str()), certificate.x5_references)
            }
            _ => (None, X5References::default()),
        };

        self.wrp_validator
            .validate_credential_issuer(
                chain,
                &schema,
                credential_category,
                x5_references,
                &self.trust_scope(organisation_id),
            )
            .await
            .error_while("validating issuer")?;

        let Some(mut interaction_data) = interaction
            .ecosystem_data
            .get::<MetadataEcosystemData>(&self.ecosystem)
            .map_err(|e| {
                HolderIssuanceError::MappingError(format!("parsing ecosystem data: {e}"))
            })?
        else {
            return Err(HolderIssuanceError::MappingError(format!(
                "No ecosystem data stored in the interaction for ecosystem `{}`",
                self.ecosystem
            )));
        };
        let validated_registration_certificate = if let Some(registration_certificate) =
            interaction_data
                .registration_certificates
                .swap_remove(credential_configuration_id)
        {
            match self
                .wrp_validator
                .validate_registration_certificate(
                    &registration_certificate,
                    &interaction_data.relying_party_id,
                    Some(&self.trust_scope(organisation_id)),
                    self.leeway,
                )
                .await
            {
                Err(err) => {
                    tracing::info!(%err, "Stored registartion certificate validation failed");
                    None
                }
                Ok(_) => Some(registration_certificate),
            }
        } else {
            None
        };

        self.store_trust_history_event(
            HistoryAction::WrpAcReceived,
            credential.id,
            organisation_id,
            Some(interaction_data.access_certificate),
            None,
        )
        .await?;

        if let Some(validated_registration_certificate) = validated_registration_certificate {
            self.store_trust_history_event(
                HistoryAction::WrpRcReceived,
                credential.id,
                organisation_id,
                Some(validated_registration_certificate),
                Some(WalletRelyingPartyMetadata {
                    name: Some(interaction_data.relying_party_name),
                    ..Default::default()
                }),
            )
            .await?;
        } else {
            let configuration = interaction_data
                .credential_configurations_supported
                .get(credential_configuration_id)
                .ok_or(HolderIssuanceError::InvalidCredentialConfiguration(
                    credential_configuration_id.to_string(),
                ))?;
            let (national_registry_data, relying_party_name) = self
                .validate_credential_config_trust_against_registry(
                    configuration,
                    &interaction_data.relying_party_id,
                    &interaction_data.registry_url,
                    organisation_id,
                )
                .await?;

            self.store_trust_history_event(
                HistoryAction::WrpNrReceived,
                credential.id,
                organisation_id,
                Some(national_registry_data),
                Some(WalletRelyingPartyMetadata {
                    name: Some(relying_party_name),
                    ..Default::default()
                }),
            )
            .await?;
        }

        Ok(())
    }

    async fn store_trust_history_event(
        &self,
        action: HistoryAction,
        credential_id: CredentialId,
        organisation_id: OrganisationId,
        blob_content: Option<String>,
        metadata: Option<WalletRelyingPartyMetadata>,
    ) -> Result<(), HolderIssuanceError> {
        let metadata_blob_id = if let Some(blob_content) = blob_content {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            let blob = Blob::new(blob_content, BlobType::HistoryMetadata);

            let blob_id = blob.id;
            blob_storage
                .create(blob)
                .await
                .error_while("creating history metadata blob")?;
            Some(blob_id)
        } else {
            None
        };

        self.history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: now_utc(),
                action,
                name: Default::default(),
                target: None,
                source: HistorySource::Core,
                entity_id: Some(credential_id.into()),
                entity_type: HistoryEntityType::Credential,
                metadata: Some(HistoryMetadata::WalletRelyingParty(
                    WalletRelyingPartyMetadata {
                        ecosystem: Some(self.ecosystem.to_owned()),
                        ..metadata.unwrap_or_default()
                    },
                )),
                metadata_blob_id,
                organisation_id: Some(organisation_id),
                user: self.session_provider.session().user(),
            })
            .await
            .error_while("storing history")?;

        Ok(())
    }
}
