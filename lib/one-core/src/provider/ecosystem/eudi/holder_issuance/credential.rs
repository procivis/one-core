use shared_types::SerializedCredential;

use super::HolderIssuanceError;
use super::metadata::MetadataEcosystemData;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::model::history::{HistoryAction, HistoryEntityType, WalletRelyingPartyMetadata};
use crate::model::interaction::Interaction;
use crate::model::relation::OptionalRelatedExt;
use crate::proto::wrp_validator::credential_category;
use crate::provider::credential_formatter::model::{IdentifierDetails, X5References};
use crate::provider::ecosystem::eudi::mapper::formatter_requires_namespaces;
use crate::provider::ecosystem::eudi::{EudiEcosystem, pid_schema_ids};

impl EudiEcosystem {
    #[tracing::instrument(level = "debug", skip_all, err(level = "debug"))]
    pub(crate) async fn resolve_credential_issuer_trust(
        &self,
        credential: &Credential,
        serialized: &SerializedCredential,
        credential_configuration_id: &String,
        interaction: &Interaction,
    ) -> Result<(), HolderIssuanceError> {
        let schema = credential.common().schema.as_ref().await?;
        let schema_format = credential.format().as_required_ref().await?;
        let format = &schema_format.format;
        let formatter = self.formatter_provider.get_credential_formatter(format)?;
        let organisation_id = interaction.organisation.id();
        // Validation uses the concrete item; trust history remains attached to its batch.
        let history_credential_id = credential.ecosystem_history_id();

        let issuer = formatter
            .extract_credentials_unverified(serialized, Some(&schema))
            .await
            .error_while("parsing credential")?
            .issuer;

        let claims = credential.claims().as_ref().await?;
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
                &schema_format,
                &pid_schema_ids(&self.params.credential_schemas, format),
                credential_category,
                x5_references,
                &self.trust_scope(organisation_id),
            )
            .await
            .error_while("validating issuer")?;

        let Some(mut interaction_data) = interaction
            .ecosystem_data
            .get::<MetadataEcosystemData>(&self.config_id)
            .map_err(|e| {
                HolderIssuanceError::MappingError(format!("parsing ecosystem data: {e}"))
            })?
        else {
            return Err(HolderIssuanceError::MappingError(format!(
                "No ecosystem data stored in the interaction for ecosystem `{}`",
                self.config_id
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
                    self.params.leeway_seconds,
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
            history_credential_id.into(),
            HistoryEntityType::Credential,
            organisation_id,
            Some(interaction_data.access_certificate),
            None,
        )
        .await?;

        if let Some(validated_registration_certificate) = validated_registration_certificate {
            self.store_trust_history_event(
                HistoryAction::WrpRcReceived,
                history_credential_id.into(),
                HistoryEntityType::Credential,
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
                history_credential_id.into(),
                HistoryEntityType::Credential,
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
}
