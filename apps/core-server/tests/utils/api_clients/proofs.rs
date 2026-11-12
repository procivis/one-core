use std::borrow::Cow;
use std::fmt::Display;

use core_server::endpoint::proof::dto::ClientIdSchemeRestEnum;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::{Value, json};
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
    pub states: Option<&'a [ProofStateEnum]>,
    pub roles: Option<&'a [ProofRole]>,
    pub proof_schema_ids: Option<&'a [ProofSchemaId]>,
    pub ids: Option<&'a [ProofId]>,
    pub verifiers: Option<&'a [IdentifierId]>,
    pub profiles: Option<&'a [&'a str]>,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub requested_date_after: Option<OffsetDateTime>,
    pub requested_date_before: Option<OffsetDateTime>,
    pub completed_date_after: Option<OffsetDateTime>,
    pub completed_date_before: Option<OffsetDateTime>,
}

#[derive(Debug, Default)]
pub struct CreateProofTestParams {
    pub proof_schema_id: Cow<'static, str>,
    pub protocol: Cow<'static, str>,
    pub verifier_did: Cow<'static, str>,
    pub redirect_uri: Option<&'static str>,
    pub verifier_key: Option<Cow<'static, str>>,
    pub profile: Option<&'static str>,
    pub iso_mdl_engagement: Option<&'static str>,
    pub engagement: Option<&'static str>,
    pub webhook_destination_url: Option<&'static str>,
    pub transaction_data: Option<Value>,
}

#[derive(Debug, Default)]
pub struct ShareProofTestParams {
    pub client_id_scheme: Option<ClientIdSchemeRestEnum>,
    pub dc_api_origin: Option<&'static str>,
}

impl ProofsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(&self, params: CreateProofTestParams) -> Response {
        let mut body = json!({
          "proofSchemaId": params.proof_schema_id,
          "protocol": params.protocol,
          "verifierDid": params.verifier_did
        });

        if let Some(redirect_uri) = params.redirect_uri {
            body["redirectUri"] = redirect_uri.into();
        }

        if let Some(verifier_key) = params.verifier_key {
            body["verifierKey"] = verifier_key.into();
        }

        if let Some(profile) = params.profile {
            body["profile"] = profile.into();
        }

        if let Some(engagement) = params.engagement {
            body["engagement"] = engagement.into();
        }

        if let Some(iso_mdl_engagement) = params.iso_mdl_engagement {
            body["isoMdlEngagement"] = iso_mdl_engagement.into();
        }

        if let Some(webhook_destination_url) = params.webhook_destination_url {
            body["webhookDestinationUrl"] = webhook_destination_url.into();
        }

        if let Some(transaction_data) = params.transaction_data {
            body["transactionData"] = transaction_data;
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

    pub async fn get_trust_detail(&self, id: &impl Display) -> Response {
        let url = format!("/api/proof-request/v1/{id}/trust-detail");
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

        if let Some(verifiers) = filters.verifiers {
            url += &verifiers.iter().fold(Default::default(), |state, elem| {
                format!("{state}&verifiers[]={elem}")
            });
        }

        if let Some(ids) = filters.proof_schema_ids {
            url += &ids.iter().fold(Default::default(), |state, elem| {
                format!("{state}&proofSchemaIds[]={elem}")
            });
        }

        if let Some(states) = filters.states {
            url += &states.iter().fold(Default::default(), |state, elem| {
                format!("{state}&states[]={}", elem.to_string().to_uppercase())
            });
        }

        if let Some(roles) = filters.roles {
            url += &roles.iter().fold(Default::default(), |state, elem| {
                format!("{state}&roles[]={}", elem.to_string().to_uppercase())
            });
        }

        if let Some(profiles) = filters.profiles {
            url += &profiles.iter().fold(Default::default(), |state, elem| {
                format!("{state}&profiles[]={elem}")
            });
        }

        if let Some(name) = filters.name {
            url += &format!("&name={name}");
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

    pub async fn share(&self, id: impl Display, params: ShareProofTestParams) -> Response {
        let url = format!("/api/proof-request/v1/{id}/share");

        let mut body_params = serde_json::Map::new();
        if let Some(client_id_scheme) = params.client_id_scheme {
            body_params.insert("clientIdScheme".to_string(), json!(client_id_scheme));
        }
        if let Some(dc_api_origin) = params.dc_api_origin {
            body_params.insert("dcApiOrigin".to_string(), dc_api_origin.into());
        }

        let body = (!body_params.is_empty()).then(|| json!({ "params": body_params }));
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

    pub async fn presentation_definition_v2(&self, id: impl Display) -> Response {
        let url = format!("/api/proof-request/v2/{id}/presentation-definition");
        self.client.get(&url).await
    }

    pub async fn transaction_data(
        &self,
        id: impl Display,
        transaction_data_id: impl Display,
    ) -> Response {
        let url = format!("/api/proof-request/v1/{id}/transaction-data/{transaction_data_id}");
        self.client.get(&url).await
    }
}
