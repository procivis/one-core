use std::fmt::Display;

use core_server::endpoint::proof::dto::ClientIdSchemeRestEnum;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::json;
use shared_types::{IdentifierId, ProofId, ProofSchemaId};
use time::OffsetDateTime;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

pub struct ProofsApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct ProofFilters<'a> {
    pub name: Option<&'a str>,
    pub proof_states: Option<&'a [ProofStateEnum]>,
    pub proof_roles: Option<&'a [ProofRole]>,
    pub proof_schema_ids: Option<&'a [ProofSchemaId]>,
    pub ids: Option<&'a [ProofId]>,
    pub profile: Option<&'a str>,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub requested_date_after: Option<OffsetDateTime>,
    pub requested_date_before: Option<OffsetDateTime>,
    pub completed_date_after: Option<OffsetDateTime>,
    pub completed_date_before: Option<OffsetDateTime>,
}

impl ProofsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        proof_schema_id: &str,
        protocol: &str,
        verifier_did: &str,
        redirect_uri: Option<&str>,
        verifier_key: Option<&str>,
        profile: Option<&str>,
    ) -> Response {
        let mut body = json!({
          "proofSchemaId": proof_schema_id,
          "protocol": protocol,
          "verifierDid": verifier_did
        });

        if let Some(redirect_uri) = redirect_uri {
            body["redirectUri"] = redirect_uri.to_string().into();
        }

        if let Some(verifier_key) = verifier_key {
            body["verifierKey"] = verifier_key.to_string().into();
        }

        if let Some(profile) = profile {
            body["profile"] = profile.to_string().into();
        }

        self.client.post("/api/proof-request/v1", body).await
    }

    pub async fn create_with_identifier(
        &self,
        proof_schema_id: &str,
        protocol: &str,
        verifier_identifier_id: &IdentifierId,
        redirect_uri: Option<&str>,
    ) -> Response {
        let mut body = json!({
          "proofSchemaId": proof_schema_id,
          "protocol": protocol,
          "verifier": verifier_identifier_id
        });

        if let Some(redirect_uri) = redirect_uri {
            body["redirectUri"] = redirect_uri.to_string().into();
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
        filters: ProofFilters<'_>,
    ) -> Response {
        let mut url = format!(
            "/api/proof-request/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}"
        );

        if let Some(ids) = filters.ids {
            url += &ids.iter().fold(Default::default(), |state, elem| {
                format!("{state}&ids[]={elem}")
            });
        }

        if let Some(ids) = filters.proof_schema_ids {
            url += &ids.iter().fold(Default::default(), |state, elem| {
                format!("{state}&proofSchemaIds[]={elem}")
            });
        }

        if let Some(states) = filters.proof_states {
            url += &states.iter().fold(Default::default(), |state, elem| {
                format!("{state}&proofStates[]={}", elem.to_string().to_uppercase())
            });
        }

        if let Some(roles) = filters.proof_roles {
            url += &roles.iter().fold(Default::default(), |state, elem| {
                format!("{state}&proofRoles[]={}", elem.to_string().to_uppercase())
            });
        }

        if let Some(name) = filters.name {
            url += &format!("&name={name}");
        }

        if let Some(profile) = filters.profile {
            url += &format!("&profile={profile}");
        }

        if let Some(date) = filters.created_date_after {
            url += &format!("&{}", query_time_urlencoded("createdDateAfter", date));
        }
        if let Some(date) = filters.created_date_before {
            url += &format!("&{}", query_time_urlencoded("createdDateBefore", date));
        }
        if let Some(date) = filters.last_modified_after {
            url += &format!("&{}", query_time_urlencoded("lastModifiedAfter", date));
        }
        if let Some(date) = filters.last_modified_before {
            url += &format!("&{}", query_time_urlencoded("lastModifiedBefore", date));
        }
        if let Some(date) = filters.requested_date_after {
            url += &format!("&{}", query_time_urlencoded("requestedDateAfter", date));
        }
        if let Some(date) = filters.requested_date_before {
            url += &format!("&{}", query_time_urlencoded("requestedDateBefore", date));
        }
        if let Some(date) = filters.completed_date_after {
            url += &format!("&{}", query_time_urlencoded("completedDateAfter", date));
        }
        if let Some(date) = filters.completed_date_before {
            url += &format!("&{}", query_time_urlencoded("completedDateBefore", date));
        }

        self.client.get(&url).await
    }

    pub async fn share(
        &self,
        id: impl Display,
        client_id_scheme: Option<ClientIdSchemeRestEnum>,
    ) -> Response {
        let url = format!("/api/proof-request/v1/{id}/share");

        let body = client_id_scheme.map(|scheme| {
            json!({
              "params": {
                "clientIdScheme": scheme
              }
            })
        });
        self.client.post(&url, body).await
    }

    pub async fn delete_proof_claims(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}/claims");
        self.client.delete(&url).await
    }

    pub async fn delete_proof(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}");
        self.client.delete(&url).await
    }

    pub async fn presentation_definition(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}/presentation-definition");
        self.client.get(&url).await
    }
}
