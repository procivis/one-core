use crate::model::credential_schema::{CredentialSchemaId, CredentialSchemaRelations};
use crate::service::error::ServiceError;
use crate::service::oidc::dto::OpenID4VCIIssuerMetadataResponseDTO;
use crate::service::oidc::mapper::create_issuer_metadata_response;
use crate::service::oidc::OIDCService;

impl OIDCService {
    pub async fn oidc_get_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<OpenID4VCIIssuerMetadataResponseDTO, ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id, &CredentialSchemaRelations::default())
            .await
            .map_err(ServiceError::from)?;

        create_issuer_metadata_response(
            self.core_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string(),
                ))?,
            &schema,
        )
    }
}
