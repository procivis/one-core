use std::fmt::Display;

use serde_json::json;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct SSIApi {
    client: HttpClient,
}

impl SSIApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn temporary_connect(&self, credential_id: impl Display) -> Response {
        let url = format!(
            "/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential={credential_id}"
        );

        self.client.post(&url, None).await
    }

    pub async fn temporary_submit(
        &self,
        credential_id: impl Display,
        did_value: impl Display,
    ) -> Response {
        let url = format!(
            "/ssi/temporary-issuer/v1/submit?credentialId={credential_id}&didValue={did_value}"
        );
        self.client.post(&url, None).await
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

    pub async fn issuer_create_credential(
        &self,
        credential_schema_id: impl Into<Uuid>,
        jwt: &str,
    ) -> Response {
        let credential_schema_id = credential_schema_id.into();
        let url = format!("/ssi/oidc-issuer/v1/{credential_schema_id}/credential");

        let body = json!({
            "format": "jwt_vc_json",
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
}
