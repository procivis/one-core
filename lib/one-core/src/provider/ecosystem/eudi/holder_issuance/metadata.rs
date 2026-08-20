use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use standardized_types::etsi_119_475;
use standardized_types::openid4vci::{
    CredentialConfiguration, CredentialIssuerMetadata, IssuerInfoAttestation,
};
use standardized_types::openid4vp::dcql;
use url::Url;

use super::{HolderIssuanceError, HolderIssuanceResolver};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::proto::wrp_validator::model::AccessCertificateResult;
use crate::provider::ecosystem::model::IssuerMetadataRepresentation;

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct MetadataEcosystemData {
    pub registration_certificates: IndexMap<String, String>,
    pub credential_configurations_supported: IndexMap<String, CredentialConfiguration>,
    pub relying_party_name: String,
    pub relying_party_id: String,
    pub registry_url: Url,
    pub access_certificate: String,
}

impl HolderIssuanceResolver {
    #[tracing::instrument(level = "debug", skip_all, err(Debug))]
    pub(crate) async fn resolve_metadata_trust(
        &self,
        interaction: &Interaction,
        issuer_metadata: &IssuerMetadataRepresentation,
        credential_configuration_ids: &[String],
    ) -> Result<(), HolderIssuanceError> {
        // only signed metadata allowed
        let (access_certificate_pem_chain, metadata) = match issuer_metadata {
            IssuerMetadataRepresentation::Unsigned(_) => {
                return Err(HolderIssuanceError::MissingIdentifier);
            }
            IssuerMetadataRepresentation::Signed(jwt) => {
                let Some(x5c) = &jwt.header.x5c else {
                    return Err(HolderIssuanceError::MissingIdentifier);
                };

                (
                    x5c_into_pem_chain(x5c).error_while("converting x5c")?,
                    &jwt.payload.custom,
                )
            }
        };

        let access_certificate = self
            .wrp_validator
            .validate_access_certificate(
                &access_certificate_pem_chain,
                Some(&self.trust_scope(interaction.organisation.id())),
            )
            .await
            .error_while("validating access certificate")?;

        let mut interaction_data: Option<MetadataEcosystemData> = None;
        for configuration_id in credential_configuration_ids {
            let configuration = metadata
                .credential_configurations_supported
                .get(configuration_id)
                .ok_or(HolderIssuanceError::MissingIdentifier)?;

            let info = self
                .validate_credential_configuration(
                    configuration,
                    metadata,
                    interaction.organisation.id(),
                    &access_certificate,
                )
                .await?;

            if let Some(current_data) = interaction_data.as_mut() {
                current_data.update(configuration_id, info)?;
            } else {
                interaction_data = Some(MetadataEcosystemData::create(
                    configuration_id,
                    info,
                    &access_certificate.relying_party_id,
                    &access_certificate_pem_chain,
                    metadata.credential_configurations_supported.to_owned(),
                ));
            };
        }

        let Some(interaction_data) = interaction_data else {
            return Err(HolderIssuanceError::NoCredentialConfiguration);
        };

        let mut ecosystem_data = interaction.ecosystem_data.to_owned();
        ecosystem_data
            .set(self.ecosystem.to_owned(), &interaction_data)
            .map_err(|e| {
                HolderIssuanceError::MappingError(format!("serializing ecosystem data: {e}"))
            })?;

        self.interaction_repository
            .update_interaction(
                interaction.id,
                UpdateInteractionRequest {
                    ecosystem_data: Some(ecosystem_data),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;

        Ok(())
    }

    async fn validate_credential_configuration(
        &self,
        configuration: &CredentialConfiguration,
        metadata: &CredentialIssuerMetadata,
        organisation_id: OrganisationId,
        access_certificate: &AccessCertificateResult,
    ) -> Result<ConfigurationTrustInfo, HolderIssuanceError> {
        Ok(if metadata.issuer_info.is_empty() {
            let registry_url = access_certificate
                .registry_url
                .as_ref()
                .ok_or(HolderIssuanceError::MissingRegistryUrl)?
                .to_owned();
            let (_national_registry_data, relying_party_name) = self
                .validate_credential_config_trust_against_registry(
                    configuration,
                    &access_certificate.relying_party_id,
                    &registry_url,
                    organisation_id,
                )
                .await?;

            ConfigurationTrustInfo {
                registration_certificate: None,
                relying_party_name,
                registry_url,
            }
        } else {
            let (registration_certificate, relying_party) = self
                .validate_credential_config_trust_with_registration_certificate(
                    configuration,
                    &metadata.issuer_info,
                    &access_certificate.relying_party_id,
                    organisation_id,
                )
                .await?;

            ConfigurationTrustInfo {
                registration_certificate: Some(registration_certificate),
                relying_party_name: relying_party.name,
                registry_url: relying_party.registry_uri,
            }
        })
    }

    pub(super) async fn validate_credential_config_trust_against_registry(
        &self,
        credential_config: &CredentialConfiguration,
        relying_party_id: &str,
        registry_url: &Url,
        organisation_id: OrganisationId,
    ) -> Result<(String, String), HolderIssuanceError> {
        let info = self
            .wrp_validator
            .fetch_from_registry(
                relying_party_id,
                registry_url,
                Some(&self.trust_scope(organisation_id)),
                self.leeway,
            )
            .await
            .error_while("fetching from WRP registry")?;

        if !info
            .payload
            .custom
            .data
            .provides_attestations
            .iter()
            .any(|attestation| {
                credential_config_matches_reg_cert_attestation(credential_config, attestation)
            })
        {
            return Err(HolderIssuanceError::DisallowedCredentialConfiguration);
        };

        Ok((
            info.jwt,
            info.payload.custom.data.trade_name.unwrap_or_default(),
        ))
    }

    async fn validate_credential_config_trust_with_registration_certificate(
        &self,
        credential_config: &CredentialConfiguration,
        issuer_info: &[IssuerInfoAttestation],
        expected_relying_party_id: &str,
        organisation_id: OrganisationId,
    ) -> Result<(String, etsi_119_475::registration_certificate::Payload), HolderIssuanceError>
    {
        for reg_cert in issuer_info {
            if let Some(relying_party) = self
                .credential_config_matches_reg_cert(
                    credential_config,
                    reg_cert,
                    expected_relying_party_id,
                    organisation_id,
                )
                .await
            {
                return Ok((reg_cert.data.to_owned(), relying_party));
            }
        }

        Err(HolderIssuanceError::DisallowedCredentialConfiguration)
    }

    async fn credential_config_matches_reg_cert(
        &self,
        credential_config: &CredentialConfiguration,
        issuer_info: &IssuerInfoAttestation,
        expected_relying_party_id: &str,
        organisation_id: OrganisationId,
    ) -> Option<etsi_119_475::registration_certificate::Payload> {
        let Ok(reg_cert) = self
            .wrp_validator
            .validate_registration_certificate(
                &issuer_info.data,
                expected_relying_party_id,
                Some(&self.trust_scope(organisation_id)),
                self.leeway,
            )
            .await
        else {
            return None;
        };

        let provides_attestations = reg_cert.payload.custom.provides_attestations.as_ref()?;

        if provides_attestations.iter().any(|attestation| {
            credential_config_matches_reg_cert_attestation(credential_config, attestation)
        }) {
            Some(reg_cert.payload.custom)
        } else {
            None
        }
    }
}

fn credential_config_matches_reg_cert_attestation(
    credential_config: &CredentialConfiguration,
    reg_cert_attestation: &etsi_119_475::Credential,
) -> bool {
    if credential_config.format != reg_cert_attestation.format.dcql_format() {
        return false;
    }

    match &reg_cert_attestation.format {
        dcql::CredentialFormat::MsoMdoc(meta) => credential_config
            .doctype
            .as_ref()
            .is_some_and(|doctype| doctype == &meta.doctype_value),
        dcql::CredentialFormat::SdJwt(meta) => credential_config
            .vct
            .as_ref()
            .is_some_and(|vct| meta.vct_values.contains(vct)),
        dcql::CredentialFormat::JwtVc(meta)
        | dcql::CredentialFormat::W3cSdJwt(meta)
        | dcql::CredentialFormat::LdpVc(meta) => credential_config
            .credential_definition
            .as_ref()
            .is_some_and(|credential_definition| {
                // TODO: support context expansion
                meta.type_values.iter().any(|types| {
                    credential_definition
                        .r#type
                        .iter()
                        .all(|r#type| types.contains(r#type))
                })
            }),
    }
}

#[derive(Debug)]
struct ConfigurationTrustInfo {
    pub registration_certificate: Option<String>,
    pub relying_party_name: String,
    pub registry_url: Url,
}

impl MetadataEcosystemData {
    fn create(
        credential_configuration_id: &str,
        info: ConfigurationTrustInfo,
        relying_party_id: &str,
        access_certificate_pem_chain: &str,
        credential_configurations_supported: IndexMap<String, CredentialConfiguration>,
    ) -> Self {
        let mut registration_certificates = IndexMap::new();
        if let Some(registration_certificate) = info.registration_certificate {
            registration_certificates.insert(
                credential_configuration_id.to_string(),
                registration_certificate,
            );
        };
        Self {
            registration_certificates,
            credential_configurations_supported,
            relying_party_name: info.relying_party_name,
            relying_party_id: relying_party_id.to_string(),
            registry_url: info.registry_url,
            access_certificate: access_certificate_pem_chain.to_string(),
        }
    }

    fn update(
        &mut self,
        credential_configuration_id: &str,
        info: ConfigurationTrustInfo,
    ) -> Result<(), HolderIssuanceError> {
        if self.relying_party_name != info.relying_party_name
            || self.registry_url != info.registry_url
        {
            return Err(HolderIssuanceError::InconsistentTrustInfo);
        }

        if let Some(registration_certificate) = info.registration_certificate {
            self.registration_certificates.insert(
                credential_configuration_id.to_string(),
                registration_certificate,
            );
        }

        Ok(())
    }
}
