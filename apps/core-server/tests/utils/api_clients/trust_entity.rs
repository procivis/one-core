use core_server::endpoint::ssi::dto::PatchTrustEntityRequestRestDTO;
use core_server::endpoint::trust_entity::dto::{
    TrustEntityRoleRest, TrustEntityStateRest, TrustEntityTypeRest,
};
use one_core::model::did::Did;
use one_core::model::identifier::Identifier;
use one_core::model::trust_anchor::TrustAnchor;
use serde_json::json;
use shared_types::{DidId, OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

pub struct TrustEntitiesApi {
    client: HttpClient,
}

#[derive(Default)]
pub struct ListFilters {
    pub role: Option<TrustEntityRoleRest>,
    pub anchor_id: Option<TrustAnchorId>,
    pub name: Option<String>,
    pub did_id: Option<DidId>,
    pub types: Option<Vec<TrustEntityTypeRest>>,
    pub entity_key: Option<String>,
    pub organisation_id: Option<OrganisationId>,
    pub states: Option<Vec<TrustEntityStateRest>>,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}

impl TrustEntitiesApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create_did(
        &self,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor: &TrustAnchor,
        r#type: Option<TrustEntityTypeRest>,
        did: &Did,
        organisation_id: OrganisationId,
    ) -> Response {
        let mut body = json!({
          "name": name,
          "role": role,
          "trustAnchorId": trust_anchor.id,
          "didId": did.id,
          "organisationId": organisation_id,
        });

        if let Some(t) = r#type {
            body["type"] = json!(t);
        }

        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn create_identifier(
        &self,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor: &TrustAnchor,
        r#type: Option<TrustEntityTypeRest>,
        identifier: &Identifier,
        organisation_id: OrganisationId,
    ) -> Response {
        let body = json!({
            "name": name,
            "role": role,
            "trustAnchorId": trust_anchor.id,
            "identifierId": identifier.id,
            "type" : r#type,
            "organisationId": organisation_id,
        });

        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn create_ca(
        &self,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor: &TrustAnchor,
        r#type: Option<TrustEntityTypeRest>,
        pem_certificate: impl AsRef<str>,
        organisation_id: OrganisationId,
    ) -> Response {
        let body = json!({
            "name": name,
            "role": role,
            "trustAnchorId": trust_anchor.id,
            "type": r#type,
            "content": pem_certificate.as_ref(),
            "organisationId": organisation_id,
        });

        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn create(&self, body: serde_json::Value) -> Response {
        self.client.post("/api/trust-entity/v1", body).await
    }

    pub async fn get(&self, id: TrustEntityId) -> Response {
        let url = format!("/api/trust-entity/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn list(&self, page: usize, filters: ListFilters) -> Response {
        let ListFilters {
            role,
            name,
            anchor_id,
            did_id,
            types,
            entity_key,
            organisation_id,
            states,
            created_date_after,
            created_date_before,
            last_modified_after,
            last_modified_before,
        } = filters;

        let mut url = format!("/api/trust-entity/v1?pageSize=20&page={page}");

        if let Some(role) = role {
            let role = match role {
                TrustEntityRoleRest::Issuer => "ISSUER",
                TrustEntityRoleRest::Verifier => "VERIFIER",
                TrustEntityRoleRest::Both => "BOTH",
            };
            url += &format!("&role={role}")
        }

        if let Some(name) = name {
            url += &format!("&name={name}")
        }

        if let Some(anchor_id) = anchor_id {
            url += &format!("&trustAnchorId={anchor_id}")
        }

        if let Some(did_id) = did_id {
            url += &format!("&didId={did_id}")
        }

        if let Some(types) = types {
            url += &types
                .into_iter()
                .map(|t| match t {
                    TrustEntityTypeRest::Did => "DID",
                    TrustEntityTypeRest::CertificateAuthority => "CA",
                })
                .enumerate()
                .map(|(i, t)| format!("&types[{i}]={t}"))
                .collect::<String>();
        }

        if let Some(states) = states {
            url += &states
                .into_iter()
                .map(|s| match s {
                    TrustEntityStateRest::Active => "ACTIVE",
                    TrustEntityStateRest::Removed => "REMOVED",
                    TrustEntityStateRest::Withdrawn => "WITHDRAWN",
                    TrustEntityStateRest::RemovedAndWithdrawn => "REMOVED_AND_WITHDRAWN",
                })
                .enumerate()
                .map(|(i, s)| format!("&states[{i}]={s}"))
                .collect::<String>();
        }

        if let Some(entity_key) = entity_key {
            url += &format!("&entityKey={entity_key}")
        }

        if let Some(organisation_id) = organisation_id {
            url += &format!("&organisationId={organisation_id}")
        }

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

        self.client.get(&url).await
    }

    pub async fn create_remote(
        &self,
        name: &str,
        role: TrustEntityRoleRest,
        trust_anchor: Option<TrustAnchor>,
        did: &Did,
        logo: Option<String>,
    ) -> Response {
        let mut body = json!({
          "name": name,
          "role": role,
          "trustAnchorId": trust_anchor.map(|anchor| anchor.id),
          "didId": did.id,
        });

        if let Some(logo) = logo {
            body["logo"] = json!(logo);
        }

        self.client.post("/api/trust-entity/remote/v1", body).await
    }

    pub async fn update(
        &self,
        id: TrustEntityId,
        request: PatchTrustEntityRequestRestDTO,
    ) -> Response {
        let body = json!(request);
        self.client
            .patch(&format!("/api/trust-entity/v1/{id}"), body)
            .await
    }

    pub async fn update_remote(
        &self,
        did: &Did,
        request: PatchTrustEntityRequestRestDTO,
    ) -> Response {
        let body = json!(request);
        self.client
            .patch(&format!("/api/trust-entity/remote/v1/{}", did.id), body)
            .await
    }

    pub async fn get_remote(&self, did: &Did) -> Response {
        self.client
            .get(&format!("/api/trust-entity/remote/v1/{}", did.id))
            .await
    }
}
