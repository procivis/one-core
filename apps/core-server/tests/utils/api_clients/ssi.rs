use axum::http::HeaderMap;
use core_server::extractor::Accept;
use headers::HeaderMapExt;
use serde_json::json;
use shared_types::{CredentialSchemaId, OrganisationId, TrustListPublicationId};
use standardized_types::openid4vci::NotificationEvent;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct SSIApi {
    client: HttpClient,
}

pub enum TokenRequest {
    PreAuthorizedCode {
        code: String,
        tx_code: Option<String>,
    },
    #[expect(unused)]
    RefreshToken(String),
}

impl SSIApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: impl Into<Uuid>,
        credential_id: impl Into<Uuid>,
    ) -> Response {
        let url = format!(
            "/ssi/openid4vci/final-1.0/{}/offer/{}",
            credential_schema_id.into(),
            credential_id.into()
        );

        self.client.get(&url).await
    }

    pub async fn get_json_ld_context(&self, credential_schema_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/context/v1/{}", credential_schema_id.into());
        self.client.get(&url).await
    }

    pub async fn get_json_ld_context_by_format(
        &self,
        credential_schema_id: impl Into<Uuid>,
        format: &str,
    ) -> Response {
        let url = format!("/ssi/context/v1/{}/{format}", credential_schema_id.into());
        self.client.get(&url).await
    }

    pub async fn get_client_request(&self, proof_id: impl Into<Uuid>) -> Response {
        let url = format!(
            "/ssi/openid4vp/final-1.0/{}/client-request",
            proof_id.into()
        );
        self.client.get(&url).await
    }

    pub async fn issuer_create_credential(
        &self,
        credential_schema_id: impl Into<Uuid>,
        credential_configuration_id: &str,
        jwt: &str,
    ) -> Response {
        self.issuer_create_credential_with_proofs(
            credential_schema_id,
            credential_configuration_id,
            &[jwt],
        )
        .await
    }

    pub async fn issuer_create_credential_with_proofs(
        &self,
        credential_schema_id: impl Into<Uuid>,
        credential_configuration_id: &str,
        jwts: &[&str],
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!("/ssi/openid4vci/final-1.0/{credential_schema_id}/credential");

        let body = json!({
            "credential_configuration_id": credential_configuration_id,
            "proofs": {
                "jwt": jwts
            },
        });

        self.client.post(&url, body).await
    }

    /// Sends a JWE encrypted Credential Request, as `application/jwt`.
    pub async fn issuer_create_credential_encrypted(
        &self,
        credential_schema_id: impl Into<Uuid>,
        jwe: String,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!("/ssi/openid4vci/final-1.0/{credential_schema_id}/credential");

        self.client.post_raw(&url, "application/jwt", jwe).await
    }

    pub async fn openid4vci_notification(
        &self,
        credential_schema_id: impl Into<Uuid>,
        notification_id: &str,
        event: NotificationEvent,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!("/ssi/openid4vci/final-1.0/{credential_schema_id}/notification");

        let body = json!({
            "notification_id": notification_id,
            "event": event
        });

        self.client.post(&url, body).await
    }

    pub async fn openid_credential_issuer_final1(
        &self,
        protocol_id: &str,
        identifier_id: impl Into<Uuid>,
        credential_schema_id: impl Into<Uuid>,
        accept: Accept,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let identifier_id = identifier_id.into();
        let url = format!(
            "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{protocol_id}/{identifier_id}/{credential_schema_id}"
        );

        let mut headers = HeaderMap::new();
        headers.typed_insert(accept);
        self.client.get_with_headers(&url, headers).await
    }

    pub async fn get_credential_schema(&self, id: impl Into<Uuid>) -> Response {
        let credential_schema_id = id.into();
        let url = format!("/ssi/schema/v1/{credential_schema_id}");

        self.client.get(&url).await
    }

    pub async fn get_credential_schema_by_format(
        &self,
        id: impl Into<Uuid>,
        format: &str,
    ) -> Response {
        let credential_schema_id = id.into();
        let url = format!("/ssi/schema/v1/{credential_schema_id}/{format}");

        self.client.get(&url).await
    }

    pub async fn get_credential_schema_v2(&self, id: impl Into<Uuid>) -> Response {
        let credential_schema_id = id.into();
        let url = format!("/ssi/schema/v2/{credential_schema_id}");

        self.client.get(&url).await
    }

    pub async fn get_credential_schema_v2_by_format(
        &self,
        id: impl Into<Uuid>,
        format: &str,
    ) -> Response {
        let credential_schema_id = id.into();
        let url = format!("/ssi/schema/v2/{credential_schema_id}/{format}");

        self.client.get(&url).await
    }

    pub async fn get_proof_schema(&self, id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/proof-schema/v1/{}", id.into());
        self.client.get(&url).await
    }

    pub async fn get_sd_jwt_vc_type_metadata(
        &self,
        organisation_id: OrganisationId,
        vct_type: impl Into<String>,
    ) -> Response {
        let url = format!("/ssi/vct/v1/{organisation_id}/{}", vct_type.into());
        self.client.get(&url).await
    }

    pub async fn get_sd_jwt_vc_type_metadata_v2(
        &self,
        organisation_id: OrganisationId,
        credential_schema_id: impl Into<String>,
        format: &str,
    ) -> Response {
        let url = format!(
            "/ssi/vct/v2/{organisation_id}/{}/{format}",
            credential_schema_id.into()
        );
        self.client.get(&url).await
    }

    pub async fn get_sd_jwt_vc_issuer_metadata(
        &self,
        protocol_id: &str,
        identifier_id: impl Into<Uuid>,
        credential_schema_id: impl Into<Uuid>,
    ) -> Response {
        let url = format!(
            "/.well-known/jwt-vc-issuer/ssi/openid4vci/{protocol_id}/{}/{}",
            identifier_id.into(),
            credential_schema_id.into()
        );
        self.client.get(&url).await
    }

    pub async fn create_token(&self, id: CredentialSchemaId, request: TokenRequest) -> Response {
        let form_data = match &request {
            TokenRequest::PreAuthorizedCode { code, tx_code } => {
                let mut data = vec![
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    ),
                    ("pre-authorized_code", code.as_str()),
                ];
                if let Some(tx_code) = tx_code {
                    data.push(("tx_code", tx_code.as_str()));
                }
                data
            }
            TokenRequest::RefreshToken(refresh_token) => vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
            ],
        };

        let url = format!("/ssi/openid4vci/final-1.0/{id}/token");

        self.client.post_form(&url, &form_data).await
    }

    pub async fn generate_nonce(&self, issuance_protocol: &str) -> Response {
        let url = format!("/ssi/openid4vci/final-1.0/{issuance_protocol}/nonce");
        self.client.post(&url, None).await
    }

    pub async fn oauth_authorization_server(
        &self,
        protocol_id: &str,
        identifier_id: impl Into<Uuid>,
        credential_schema_id: impl Into<Uuid>,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let identifier_id = identifier_id.into();
        let url = format!(
            "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{protocol_id}/{identifier_id}/{credential_schema_id}"
        );
        self.client.get(&url).await
    }

    pub async fn get_wallet_provider_metadata(&self, wallet_provider: impl AsRef<str>) -> Response {
        let wallet_provider = wallet_provider.as_ref();
        let url = format!("/ssi/wallet-provider/v1/{}", wallet_provider);
        self.client.get(&url).await
    }

    pub async fn get_revocation_list(&self, revocation_list_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/revocation/v1/list/{}", revocation_list_id.into());
        self.client.get(&url).await
    }

    pub async fn get_crl(&self, revocation_list_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/revocation/v1/crl/{}", revocation_list_id.into());
        self.client.get(&url).await
    }

    pub async fn get_ca(&self, ca_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/ca/{}", ca_id.into());
        self.client.get(&url).await
    }

    pub async fn get_certificate(&self, certificate_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/certificate/{}", certificate_id.into());
        self.client.get(&url).await
    }

    pub async fn get_verifier_provider(&self, id: &str) -> Response {
        let url = format!("/ssi/verifier-provider/v1/{}", id);
        self.client.get(&url).await
    }

    pub async fn get_trust_list_publication_content(
        &self,
        id: TrustListPublicationId,
        accept: Accept,
    ) -> Response {
        let url = format!("/ssi/trust-list/v1/{}", id);
        let mut headers = HeaderMap::new();
        headers.typed_insert(accept);
        self.client.get_with_headers(&url, headers).await
    }

    pub async fn get_trust_collection(&self, trust_collection_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/trust-collection/v1/{}", trust_collection_id.into());
        self.client.get(&url).await
    }
}
