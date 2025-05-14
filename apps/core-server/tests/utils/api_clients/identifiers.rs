use serde_json::json;
use shared_types::{IdentifierId, KeyId, OrganisationId};

use super::{HttpClient, Response};

pub struct IdentifiersApi {
    client: HttpClient,
}

impl IdentifiersApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create_key_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "keyId": key_id,
                    "organisationId": organisation_id
                }),
            )
            .await
    }

    pub async fn create_certificate_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
        chain: &str,
    ) -> Response {
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "organisationId": organisation_id,
                    "certificates": [{
                        "chain": chain,
                        "keyId": key_id
                    }]
                }),
            )
            .await
    }

    pub async fn get(&self, id: &IdentifierId) -> Response {
        self.client.get(&format!("/api/identifier/v1/{}", id)).await
    }

    pub async fn delete(&self, id: &IdentifierId) -> Response {
        self.client
            .delete(&format!("/api/identifier/v1/{}", id))
            .await
    }
}
