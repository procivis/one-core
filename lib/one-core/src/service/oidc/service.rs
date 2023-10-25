use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaId, CredentialSchemaRelations,
};
use crate::service::error::ServiceError;
use crate::service::oidc::{
    dto::{OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataResponseDTO},
    mapper::{create_issuer_metadata_response, create_service_discovery_response},
    OIDCService,
};

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
}
