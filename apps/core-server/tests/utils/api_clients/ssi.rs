use std::fmt::Display;

use serde_json::json;
use shared_types::CredentialSchemaId;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct SSIApi {
    client: HttpClient,
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
            "/ssi/oidc-issuer/v1/{}/offer/{}",
            credential_schema_id.into(),
            credential_id.into()
        );

        self.client.get(&url).await
    }

    pub async fn get_json_ld_context(&self, credential_schema_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/context/v1/{}", credential_schema_id.into());
        self.client.get(&url).await
    }

    pub async fn get_oidc_verifier_presentation_definition(
        &self,
        proof_id: impl Display,
    ) -> Response {
        let url = format!("/ssi/oidc-verifier/v1/{proof_id}/presentation-definition");
        self.client.get(&url).await
    }

    pub async fn get_client_metadata(&self, proof_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/oidc-verifier/v1/{}/client-metadata", proof_id.into());
        self.client.get(&url).await
    }

    pub async fn get_client_request(&self, proof_id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/oidc-verifier/v1/{}/client-request", proof_id.into());
        self.client.get(&url).await
    }

    pub async fn issuer_create_credential(
        &self,
        credential_schema_id: impl Into<Uuid>,
        format: &str,
        jwt: &str,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!("/ssi/oidc-issuer/v1/{credential_schema_id}/credential");

        let body = json!({
            "format": format,
            "credential_definition": {
                "type": ["VerifiableCredential"]
            },
            "proof": {
                "proof_type": "jwt",
                "jwt": jwt
            },
        });

        self.client.post(&url, body).await
    }

    pub async fn issuer_create_credential_mdoc(
        &self,
        credential_schema_id: impl Into<Uuid>,
        doctype: &str,
        jwt: &str,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!("/ssi/oidc-issuer/v1/{credential_schema_id}/credential");

        let body = json!({
            "format": "mso_mdoc",
            "credential_definition": {
                "type": ["VerifiableCredential"]
            },
            "proof": {
                "proof_type": "jwt",
                "jwt": jwt
            },
            "doctype": doctype
        });

        self.client.post(&url, body).await
    }

    pub async fn openid_credential_issuer(
        &self,
        credential_schema_id: impl Into<Uuid>,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!(
            "/ssi/oidc-issuer/v1/{credential_schema_id}/.well-known/openid-credential-issuer"
        );
        self.client.get(&url).await
    }

    pub async fn get_credential_schema(&self, id: impl Into<Uuid>) -> Response {
        let credential_schema_id = id.into();
        let url = format!("/ssi/schema/v1/{credential_schema_id}");

        self.client.get(&url).await
    }

    pub async fn get_trust_list(&self, id: impl Into<Uuid>) -> Response {
        let trust_anchor_id = id.into();
        let url = format!("/ssi/trust/v1/{trust_anchor_id}");

        self.client.get(&url).await
    }

    pub async fn get_proof_schema(&self, id: impl Into<Uuid>) -> Response {
        let url = format!("/ssi/proof-schema/v1/{}", id.into());
        self.client.get(&url).await
    }

    pub async fn create_token(
        &self,
        id: CredentialSchemaId,
        pre_authorized_code: Option<&str>,
        refresh_token: Option<&str>,
    ) -> Response {
        let form_data = match (pre_authorized_code, refresh_token) {
            (Some(_), Some(_)) => {
                panic!("Only one of `pre_authorized_code` or `refresh_token` must be present")
            }
            (None, None) => {
                panic!("One of `pre_authorized_code` or `refresh_token` must be present")
            }

            (Some(pre_authorized_code), _) => [
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                ),
                ("pre-authorized_code", pre_authorized_code),
            ],
            (_, Some(refresh_token)) => [
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ],
        };

        let url = format!("/ssi/oidc-issuer/v1/{id}/token");

        self.client.post_form(&url, &form_data).await
    }
}
