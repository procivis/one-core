use shared_types::{CredentialId, CredentialSchemaId, IdentifierId};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::token::{TokenRequest, TokenResponse};
use standardized_types::openid4vci::{CredentialOffer, NonceResponse, NotificationRequest};

use super::OID4VCIFinal1_0SwiyuService;
use crate::service::oid4vci_final1_0::dto::{
    CredentialRequestPayload, CredentialResponsePayload, OID4VCIFinal1_0IssuerMetadataResponseEnum,
    OID4VCIFinal1_0MetadataResponseTypeEnum,
};
use crate::service::oid4vci_final1_0::error::OID4VCIFinal1_0ServiceError;

impl OID4VCIFinal1_0SwiyuService {
    pub async fn oauth_authorization_server(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<AuthorizationServerMetadata, OID4VCIFinal1_0ServiceError> {
        self.inner
            .oauth_authorization_server(protocol_id, identifier_id, credential_schema_id)
            .await
    }
    pub async fn get_issuer_metadata(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
        response_type: OID4VCIFinal1_0MetadataResponseTypeEnum,
    ) -> Result<OID4VCIFinal1_0IssuerMetadataResponseEnum, OID4VCIFinal1_0ServiceError> {
        self.inner
            .get_issuer_metadata(
                protocol_id,
                identifier_id,
                credential_schema_id,
                response_type,
            )
            .await
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<CredentialOffer, OID4VCIFinal1_0ServiceError> {
        self.inner
            .get_credential_offer(credential_schema_id, credential_id)
            .await
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: TokenRequest,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
    ) -> Result<TokenResponse, OID4VCIFinal1_0ServiceError> {
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
        request: CredentialRequestPayload,
    ) -> Result<CredentialResponsePayload, OID4VCIFinal1_0ServiceError> {
        self.inner
            .create_credential(credential_schema_id, access_token, request)
            .await
    }

    pub async fn generate_nonce(
        &self,
        protocol_id: &str,
    ) -> Result<NonceResponse, OID4VCIFinal1_0ServiceError> {
        self.inner.generate_nonce(protocol_id).await
    }

    pub async fn handle_notification(
        &self,
        credential_schema_id: CredentialSchemaId,
        access_token: &str,
        request: NotificationRequest,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        self.inner
            .handle_notification(credential_schema_id, access_token, request)
            .await
    }
}
