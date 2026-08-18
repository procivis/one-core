use std::fmt::Display;

use serde::Serialize;
use serde_json::json;
use serde_with::skip_serializing_none;
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

#[derive(Debug, Clone)]
pub struct OrganisationFilters {
    pub page: u64,
    pub page_size: u64,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub has_parent_organisation: Option<bool>,
    pub parent_organisations: Option<Vec<OrganisationId>>,
}

pub struct OrganisationsApi {
    client: HttpClient,
}

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderParams {
    pub name: Option<String>,
    pub issuer: Option<IdentifierId>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertOrganisationConfigurationParams {
    pub trusted_issuer_required: Option<bool>,
    pub trusted_rp_required: Option<bool>,
    pub trusted_wallet_provider_required: Option<bool>,
    pub enforce_ecosystem_as_issuer: Option<bool>,
    pub enforce_ecosystem_as_holder: Option<bool>,
    pub enforce_ecosystem_as_verifier: Option<bool>,
}

#[skip_serializing_none]
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertParams {
    pub deactivate: Option<bool>,
    pub wallet_provider: Option<Option<ProviderParams>>,
    pub verifier_provider: Option<Option<ProviderParams>>,
    pub configuration: Option<UpsertOrganisationConfigurationParams>,
    pub trust_collections: Option<Vec<shared_types::TrustCollectionId>>,
    pub parent_organisation: Option<Option<OrganisationId>>,
}

impl OrganisationsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, id: impl Into<Option<Uuid>>) -> Response {
        self.create_with_parent(id, None).await
    }

    pub async fn create_with_parent(
        &self,
        id: impl Into<Option<Uuid>>,
        parent_organisation: Option<OrganisationId>,
    ) -> Response {
        let mut body = match id.into() {
            Some(id) => json!({"id": id}),
            None => json!({}),
        };

        if let Some(parent) = parent_organisation {
            body["parentOrganisation"] = json!(parent);
        }

        self.client.post("/api/organisation/v1", body).await
    }

    pub async fn upsert(&self, id: &impl Display, params: UpsertParams) -> Response {
        self.client
            .patch(
                &format!("/api/organisation/v1/{id}"),
                Some(serde_json::to_value(params).unwrap()),
            )
            .await
    }

    pub async fn list(
        &self,
        OrganisationFilters {
            page,
            page_size,
            created_date_after,
            created_date_before,
            last_modified_after,
            last_modified_before,
            has_parent_organisation,
            parent_organisations,
        }: OrganisationFilters,
    ) -> Response {
        let mut url = format!("/api/organisation/v1?page={page}&pageSize={page_size}");

        if let Some(date) = created_date_after {
            url += &format!("&{}", query_time_urlencoded("createdDateAfter", date));
        }
        if let Some(date) = created_date_before {
            url += &format!("&{}", query_time_urlencoded("createdDateBefore", date));
        }
        if let Some(date) = last_modified_after {
            url += &format!("&{}", query_time_urlencoded("lastModifiedAfter", date));
        }
        if let Some(date) = last_modified_before {
            url += &format!("&{}", query_time_urlencoded("lastModifiedBefore", date));
        }
        if let Some(value) = has_parent_organisation {
            url += &format!("&hasParentOrganisation={value}");
        }
        if let Some(parent_organisations) = parent_organisations {
            for id in parent_organisations {
                url += &format!("&parentOrganisations[]={id}");
            }
        }

        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/organisation/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn get_trust_collections(&self, id: &impl Display) -> Response {
        let url = format!("/api/organisation/v1/{id}/trust-collections");
        self.client.get(&url).await
    }

    pub async fn get_ecosystems(&self, id: &impl Display) -> Response {
        let url = format!("/api/organisation/v1/{id}/ecosystems");
        self.client.get(&url).await
    }
}
