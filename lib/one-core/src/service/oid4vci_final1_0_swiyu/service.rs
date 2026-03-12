use shared_types::{CredentialId, CredentialSchemaId};

use super::OID4VCIFinal1_0SwiyuService;
use super::mapper::to_swiyu_data_type;
use crate::error::ContextWithErrorCode;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestDTO, OpenID4VCIFinal1CredentialOfferDTO,
    OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCINonceResponseDTO,
    OpenID4VCINotificationRequestDTO, OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
};
use crate::service::oid4vci_final1_0::dto::{
    OAuthAuthorizationServerMetadataResponseDTO, OpenID4VCICredentialResponseDTO,
};
use crate::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;

impl OID4VCIFinal1_0SwiyuService {
    pub async fn oauth_authorization_server(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OAuthAuthorizationServerMetadataResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .oauth_authorization_server(protocol_id, credential_schema_id)
            .await
    }
    pub async fn get_issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, OID4VCIFinal1_0ServiceError> {
        let mut metadata = self
            .inner
            .get_issuer_metadata(protocol_id, credential_schema_id)
            .await?;
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(
                credential_schema_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations::default()),
                    organisation: None,
                },
            )
            .await
            .error_while("loading credential schema")?
            .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                "credential schema not found".to_string(),
            ))?;
        let credential_schema_claims =
            credential_schema
                .claim_schemas
                .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                    "missing credential schema claims".to_string(),
                ))?;

        // make formats compatible to the swiyu wallet
        for (key, credential_config) in metadata.credential_configurations_supported.iter_mut() {
            if key != &credential_schema.schema_id {
                // only adjust the schema referenced in the id
                continue;
            }
            if credential_config.format == "dc+sd-jwt" {
                credential_config.format = "vc+sd-jwt".to_string();
            }
            let Some(meta) = credential_config.credential_metadata.as_mut() else {
                continue;
            };
            let Some(claims) = meta.claims.as_mut() else {
                continue;
            };
            for claim in claims {
                let Some(schema) = credential_schema_claims
                    .iter()
                    .find(|cs| cs.key == claim.path.join("/"))
                else {
                    continue;
                };
                let data_type = self
                    .config
                    .datatype
                    .get_type(&schema.data_type)
                    .error_while("getting claim data type")?;
                let additional_values = claim.additional_values.get_or_insert_default();
                additional_values.insert(
                    "value_type".to_string(),
                    serde_json::json!(to_swiyu_data_type(data_type)?),
                );
            }
        }

        Ok(metadata)
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<OpenID4VCIFinal1CredentialOfferDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .get_credential_offer(credential_schema_id, credential_id)
            .await
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: OpenID4VCITokenRequestDTO,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
    ) -> Result<OpenID4VCITokenResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .create_token(
                credential_schema_id,
                request,
                oauth_client_attestation,
                oauth_client_attestation_pop,
            )
            .await
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCICredentialRequestDTO,
    ) -> Result<OpenID4VCICredentialResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner
            .create_credential(credential_schema_id, access_token, request)
            .await
    }

    pub async fn generate_nonce(
        &self,
        protocol_id: &str,
    ) -> Result<OpenID4VCINonceResponseDTO, OID4VCIFinal1_0ServiceError> {
        self.inner.generate_nonce(protocol_id).await
    }

    pub async fn handle_notification(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: OpenID4VCINotificationRequestDTO,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        self.inner
            .handle_notification(credential_schema_id, access_token, request)
            .await
    }
}
