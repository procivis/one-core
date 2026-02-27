use std::str::FromStr;

use shared_types::{CredentialId, CredentialSchemaId};
use uuid::Uuid;

use crate::error::ContextWithErrorCode;
use crate::model::common::LockType;
use crate::model::interaction::{Interaction, InteractionRelations};
use crate::provider::issuance_protocol::error::{OpenID4VCIError, OpenIDIssuanceError};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
};
use crate::service::error::ServiceError;
use crate::service::oid4vci_draft13::dto::OAuthAuthorizationServerMetadataResponseDTO;
use crate::service::oid4vci_draft13_swiyu::OID4VCIDraft13SwiyuService;
use crate::service::oid4vci_draft13_swiyu::dto::OpenID4VCISwiyuCredentialResponseDTO;

impl OID4VCIDraft13SwiyuService {
    pub async fn oauth_authorization_server(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OAuthAuthorizationServerMetadataResponseDTO, ServiceError> {
        self.inner
            .oauth_authorization_server(credential_schema_id)
            .await
    }
    pub async fn get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        let mut metadata = self.inner.get_issuer_metadata(credential_schema_id).await?;

        // make claim datatypes compatible to the swiyu wallet
        metadata
            .credential_configurations_supported
            .iter_mut()
            .for_each(|(_, config)| {
                if let Some(ref mut claims) = config.claims {
                    set_value_type_string(claims);
                }
            });

        Ok(metadata)
    }

    pub async fn service_discovery(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIDiscoveryResponseDTO, ServiceError> {
        self.inner.service_discovery(credential_schema_id).await
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<OpenID4VCICredentialOfferDTO, ServiceError> {
        self.inner
            .get_credential_offer(credential_schema_id, credential_id)
            .await
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
    ) -> Result<OpenID4VCITokenResponseDTO, ServiceError> {
        let interaction_id = match &request {
            OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                pre_authorized_code,
                tx_code: _,
            } => Uuid::from_str(pre_authorized_code)
                .map_err(|_| {
                    ServiceError::OpenIDIssuanceError(OpenIDIssuanceError::OpenID4VCI(
                        OpenID4VCIError::InvalidRequest,
                    ))
                })?
                .into(),
            _ => {
                return Err(ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidGrant));
            }
        };
        let mut response = self
            .inner
            .create_token(credential_schema_id, request)
            .await?;
        response.c_nonce = None;
        let mut interaction = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations::default(),
                Some(LockType::Update),
            )
            .await
            .error_while("getting interaction")?
            .ok_or(ServiceError::MappingError(format!(
                "Interaction `{}` not found",
                interaction_id
            )))?;
        let mut parsed_data = interaction_data_to_dto(&interaction)?;
        parsed_data.nonce = None;
        let data = serde_json::to_vec(&parsed_data)
            .map_err(|e| ServiceError::MappingError(e.to_string()))?;
        interaction.data = Some(data);

        self.interaction_repository
            .update_interaction(interaction.id, interaction.into())
            .await
            .error_while("updating interaction")?;
        Ok(response)
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        mut request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCISwiyuCredentialResponseDTO, ServiceError> {
        if request.vct.is_none() {
            request.vct = request
                .credential_definition
                .iter()
                .flat_map(|def| def.r#type.clone())
                .next();
        }
        let regular_dto = self
            .inner
            .create_credential(credential_schema_id, access_token, request)
            .await?;
        Ok(OpenID4VCISwiyuCredentialResponseDTO {
            credential: regular_dto.credential,
            // This field is non-standard and SWIYU only supports SD-JWT VC
            format: "vc+sd-jwt".to_owned(),
            redirect_uri: regular_dto.redirect_uri,
        })
    }
}

pub(crate) fn interaction_data_to_dto(
    interaction: &Interaction,
) -> Result<OpenID4VCIIssuerInteractionDataDTO, ServiceError> {
    let interaction_data = interaction
        .data
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "interaction data is missing".to_string(),
        ))?;

    serde_json::from_slice(&interaction_data).map_err(|e| ServiceError::MappingError(e.to_string()))
}

fn set_value_type_string(claims: &mut OpenID4VCICredentialSubjectItem) {
    match claims.value_type.as_mut() {
        None => {}
        Some(value_type) if *value_type == "swiyu_picture" => {
            *value_type = "image/jpeg".to_string()
        }
        Some(value_type) => *value_type = "string".to_owned(),
    }
    if let Some(ref mut inner_claims) = claims.claims {
        inner_claims
            .iter_mut()
            .for_each(|(_, claims)| set_value_type_string(claims))
    }
}
