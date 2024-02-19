use serde_json::json;
use std::fmt::Display;

use uuid::Uuid;

use super::{HttpClient, Response};

pub struct ProofsApi {
    client: HttpClient,
}

impl ProofsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        proof_schema_id: &str,
        transport: &str,
        verifier_did: &str,
        redirect_uri: Option<&str>,
        verifier_key: Option<&str>,
    ) -> Response {
        let mut body = json!({
          "proofSchemaId": proof_schema_id,
          "transport": transport,
          "verifierDid": verifier_did
        });

        if let Some(redirect_uri) = redirect_uri {
            body["redirectUri"] = redirect_uri.to_string().into();
        }

        if let Some(verifier_key) = verifier_key {
            body["verifierKey"] = verifier_key.to_string().into();
        }

        self.client.post("/api/proof-request/v1", body).await
    }

    pub async fn get(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn list(
        &self,
        page: u32,
        page_size: u32,
        organisation_id: &impl Display,
        ids: impl IntoIterator<Item = &Uuid>,
    ) -> Response {
        let mut url = format!(
            "/api/proof-request/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        for id in ids {
            url += &format!("&ids[]={id}")
        }

        self.client.get(&url).await
    }
}
