use shared_types::{CredentialId, CredentialSchemaId};

use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCIDiscoveryResponseDTO, OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCITokenRequestDTO,
    OpenID4VCITokenResponseDTO,
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

        // SWIYU Android wallet cannot handle any other values than ES256 and ES512
        metadata
            .credential_configurations_supported
            .iter_mut()
            .for_each(|(_, config)| {
                config.credential_signing_alg_values_supported = Some(
                    config
                        .credential_signing_alg_values_supported
                        .clone()
                        .into_iter()
                        .flat_map(|algs| algs.into_iter().filter(only_p256_or_p512))
                        .collect(),
                );
                if let Some(proof_config) = &mut config.proof_types_supported {
                    proof_config.iter_mut().for_each(|(_, cfg)| {
                        cfg.proof_signing_alg_values_supported = cfg
                            .proof_signing_alg_values_supported
                            .clone()
                            .into_iter()
                            .filter(only_p256_or_p512)
                            .collect();
                    })
                }
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
        self.inner.create_token(credential_schema_id, request).await
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

fn only_p256_or_p512(alg: &String) -> bool {
    alg == "ES256" || alg == "ES512"
}
