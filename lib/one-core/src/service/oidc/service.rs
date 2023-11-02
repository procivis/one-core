use crate::common_mapper::{
    get_exchange_param_pre_authorization_expires_in, get_exchange_param_token_expires_in,
};
use crate::common_validator::throw_if_latest_credential_state_not_eq;
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaId, CredentialSchemaRelations,
};
use crate::model::interaction::InteractionRelations;
use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;
use crate::service::oidc::dto::{OpenID4VCICredentialRequestDTO, OpenID4VCICredentialResponseDTO};
use crate::service::oidc::mapper::{interaction_data_to_dto, parse_authorization_header};
use crate::service::oidc::validator::{
    throw_if_credential_request_invalid, throw_if_interaction_created_date,
    throw_if_interaction_data_invalid, throw_if_interaction_pre_authorized_code_used,
    throw_if_token_request_invalid,
};
use crate::service::oidc::{
    dto::{
        OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataResponseDTO,
        OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
    },
    mapper::{create_issuer_metadata_response, create_service_discovery_response},
    OIDCService,
};
use std::ops::Add;
use std::str::FromStr;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

impl OIDCService {
    pub async fn oidc_get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        let (base_url, schema) = self
            .get_credential_schema_base_url(credential_schema_id)
            .await?;

        create_issuer_metadata_response(base_url, schema)
    }

    pub async fn oidc_service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
        let (base_url, _) = self
            .get_credential_schema_base_url(credential_schema_id)
            .await?;

        create_service_discovery_response(base_url)
    }

    async fn get_credential_schema_base_url(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<(String, CredentialSchema), ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await?;

        let core_base_url = self
            .core_base_url
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "Host URL not specified".to_string(),
            ))?;

        Ok((
            format!("{}/ssi/oidc-issuer/v1/{}", core_base_url, schema.id),
            schema,
        ))
    }

    pub async fn oidc_create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        authorization: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await
            .map_err(ServiceError::from)?;

        throw_if_credential_request_invalid(&schema, &request)?;

        let authorization_parts = parse_authorization_header(authorization)?;

        let interaction = self
            .interaction_repository
            .get_interaction(&authorization_parts.1, &InteractionRelations::default())
            .await
            .map_err(ServiceError::from)?;

        throw_if_interaction_data_invalid(
            &interaction_data_to_dto(&interaction)?,
            authorization_parts,
        )?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction.id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations::default()),
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        if credentials.is_empty() {
            return Err(ServiceError::NotFound);
        }

        let credential = self
            .protocol_provider
            .issue_credential(&credentials.get(0).ok_or(ServiceError::NotFound)?.id)
            .await?;

        Ok(OpenID4VCICredentialResponseDTO {
            credential: credential.credential,
            format: request.format,
        })
    }

    pub async fn oidc_create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
    ) -> Result<OpenID4VCITokenResponseDTO, ServiceError> {
        throw_if_token_request_invalid(&request)?;

        self.credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await
            .map_err(ServiceError::from)?;

        let interaction_id = Uuid::from_str(&request.pre_authorized_code)
            .map_err(|_| DataLayerError::MappingError)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations::default()),
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        if credentials.is_empty() {
            return Err(ServiceError::NotFound);
        }
        let now = OffsetDateTime::now_utc();

        let mut interaction = credentials
            .get(0)
            .ok_or(ServiceError::MappingError("credentials none".to_string()))?
            .interaction
            .clone()
            .ok_or(ServiceError::MappingError(
                "interaction is None".to_string(),
            ))?;

        throw_if_interaction_created_date(
            get_exchange_param_pre_authorization_expires_in(&self.config)?,
            &interaction,
        )?;

        let mut interaction_data = interaction_data_to_dto(&interaction)?;

        throw_if_interaction_pre_authorized_code_used(&interaction_data)?;

        for credential in &credentials {
            throw_if_latest_credential_state_not_eq(credential, CredentialStateEnum::Pending)?;
            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: now,
                        state: CredentialStateEnum::Offered,
                    }),
                    ..Default::default()
                })
                .await?;
        }

        interaction_data.pre_authorized_code_used = true;
        interaction_data.access_token_expires_at = now.add(Duration::from_secs(
            get_exchange_param_token_expires_in(&self.config)?,
        ));

        let data = serde_json::to_vec(&interaction_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;

        interaction.data = Some(data);

        self.interaction_repository
            .update_interaction(interaction)
            .await?;

        Ok(interaction_data.into())
    }
}
