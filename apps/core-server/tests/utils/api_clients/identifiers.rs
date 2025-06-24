use serde_json::json;
use shared_types::{CertificateId, IdentifierId, KeyId, OrganisationId};

use super::{HttpClient, Response};

pub struct IdentifiersApi {
    client: HttpClient,
}

impl IdentifiersApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create_did_identifier(
        &self,
        name: &str,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> Response {
        let did_name = format!("did-{}", name);
        self.client
            .post(
                "/api/identifier/v1",
                json!( {
                    "name": name,
                    "did": {
                      "keys": {
                        "assertionMethod": [
                          key_id
                        ],
                        "authentication": [
                          key_id
                        ],
                        "capabilityDelegation": [
                          key_id
                        ],
                        "capabilityInvocation": [
                          key_id
                        ],
                        "keyAgreement": [
                          key_id
                        ]
                      },
                      "method": "KEY",
                      "name": did_name,
                      "organisationId": organisation_id,
                      "params": {}
                    },
                    "organisationId": organisation_id
                }),
            )
            .await
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

    pub async fn list_by_key_storage_type(
        &self,
        key_storage_type: &str,
        organisation_id: OrganisationId,
    ) -> Response {
        self.client.get(
            &format!("/api/identifier/v1?page=0&pageSize=30&keyStorages%5B%5D={key_storage_type}&organisationId={organisation_id}")).await
    }

    pub async fn resolve_trust_entities(
        &self,
        identifiers: &[(IdentifierId, Option<CertificateId>)],
    ) -> Response {
        let identifiers: Vec<_> = identifiers
            .iter()
            .map(|(identifier, cert)| {
                let mut value = json!( {
                    "id": identifier,
                });
                if let Some(cert) = cert {
                    value["certificateId"] = json!(cert);
                }
                value
            })
            .collect();

        self.client
            .post(
                "/api/identifier/v1/resolve-trust-entity",
                json!( {
                    "identifiers": identifiers,
                    }
                ),
            )
            .await
    }
}
