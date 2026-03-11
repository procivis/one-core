use core_server::endpoint::trust_list_publication::dto::{
    TrustEntryStatusRestEnum, TrustListPublicationRoleRestEnum,
};
use serde_json::json;
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};

use super::{HttpClient, Response};

pub struct TrustListPublicationApi {
    client: HttpClient,
}

#[derive(Debug)]
pub struct CreateTrustListPublicationTestParams<'a> {
    pub organisation_id: OrganisationId,
    pub identifier_id: IdentifierId,
    pub name: &'a str,
    pub role: TrustListPublicationRoleRestEnum,
    pub r#type: TrustListPublisherId,
    pub key_id: Option<KeyId>,
    pub certificate_id: Option<CertificateId>,
    pub params: Option<serde_json::Value>,
}

impl TrustListPublicationApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create_trust_list_publication(
        &self,
        params: CreateTrustListPublicationTestParams<'_>,
    ) -> Response {
        let mut body = json!({
            "organisationId": params.organisation_id,
            "identifierId": params.identifier_id,
            "name": params.name,
            "role": params.role,
            "type": r#params.r#type,
        });
        if let Some(key_id) = params.key_id {
            body["keyId"] = serde_json::Value::String(key_id.to_string());
        }
        if let Some(certificate_id) = params.certificate_id {
            body["certificateId"] = serde_json::Value::String(certificate_id.to_string());
        }
        if let Some(params) = params.params {
            body["params"] = params;
        }
        self.client.post("/api/trust-list/v1", body).await
    }

    pub async fn get_trust_list_publication(&self, id: TrustListPublicationId) -> Response {
        self.client.get(&format!("/api/trust-list/v1/{id}")).await
    }

    pub async fn get_trust_list_publications(&self, query: Option<String>) -> Response {
        let path = if let Some(query) = query {
            format!("/api/trust-list/v1?pageSize=20&page=0&{query}")
        } else {
            "/api/trust-list/v1?pageSize=20&page=0".to_string()
        };
        self.client.get(&path).await
    }

    pub async fn delete_trust_list_publication(&self, id: TrustListPublicationId) -> Response {
        self.client
            .delete(&format!("/api/trust-list/v1/{id}"))
            .await
    }

    pub async fn create_trust_entry(
        &self,
        trust_list_id: TrustListPublicationId,
        identifier_id: IdentifierId,
        params: Option<serde_json::Value>,
    ) -> Response {
        let body = json!({
            "identifierId": identifier_id,
            "params": params,
        });

        self.client
            .post(&format!("/api/trust-list/v1/{trust_list_id}/entry"), body)
            .await
    }

    pub async fn update_trust_entry(
        &self,
        trust_list_id: TrustListPublicationId,
        entry_id: TrustEntryId,
        status: Option<TrustEntryStatusRestEnum>,
        params: Option<serde_json::Value>,
    ) -> Response {
        let body = json!({
            "status": status,
            "params": params,
        });

        self.client
            .patch(
                &format!("/api/trust-list/v1/{trust_list_id}/entry/{entry_id}"),
                body,
            )
            .await
    }

    pub async fn delete_trust_entry(
        &self,
        trust_list_id: TrustListPublicationId,
        entry_id: TrustEntryId,
    ) -> Response {
        self.client
            .delete(&format!(
                "/api/trust-list/v1/{trust_list_id}/entry/{entry_id}"
            ))
            .await
    }

    pub async fn get_trust_list_publication_entries(
        &self,
        id: TrustListPublicationId,
        query: Option<String>,
    ) -> Response {
        let path = if let Some(query) = query {
            format!("/api/trust-list/v1/{id}/entry?pageSize=20&page=0&{query}")
        } else {
            format!("/api/trust-list/v1/{id}/entry?pageSize=20&page=0")
        };
        self.client.get(&path).await
    }
}
