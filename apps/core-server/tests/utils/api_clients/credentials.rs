use std::fmt::Display;

use one_core::model::credential::CredentialListIncludeEntityTypeEnum;
use serde_json::json;
use shared_types::{CertificateId, CredentialId, DidId, IdentifierId, KeyId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{HttpClient, Response};
use crate::utils::serialization::query_time_urlencoded;

pub struct CredentialsApi {
    client: HttpClient,
}

#[derive(Debug, Default)]
pub struct Filters<'a> {
    pub name: Option<&'a str>,
    pub search_text: Option<&'a str>,
    pub search_type: Option<&'a [&'a str]>,
    pub profiles: Option<&'a [&'a str]>,
    pub roles: Option<&'a [&'a str]>,
    pub credential_schema_ids: Option<&'a [&'a str]>,
    pub ids: Option<&'a [CredentialId]>,
    pub issuers: Option<&'a [IdentifierId]>,
    pub states: Option<&'a [&'a str]>,

    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
    pub issuance_date_after: Option<OffsetDateTime>,
    pub issuance_date_before: Option<OffsetDateTime>,
    pub revocation_date_after: Option<OffsetDateTime>,
    pub revocation_date_before: Option<OffsetDateTime>,
}

impl<'a> Filters<'a> {
    pub fn ids(ids: &'a [CredentialId]) -> Self {
        Self {
            ids: Some(ids),
            ..Self::default()
        }
    }

    pub fn roles(roles: &'a [&'a str]) -> Self {
        Self {
            roles: Some(roles),
            ..Self::default()
        }
    }

    pub fn none() -> Self {
        Self::default()
    }
}

impl CredentialsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        credential_schema_id: impl Into<Uuid>,
        protocol: impl Into<String>,
        issuer: impl Into<Option<IdentifierId>>,
        claims: serde_json::Value,
        issuer_did: impl Into<Option<DidId>>,
        issuer_key: impl Into<Option<KeyId>>,
        issuer_certificate: impl Into<Option<CertificateId>>,
        profile: Option<&str>,
    ) -> Response {
        let mut body = json!({
          "credentialSchemaId": credential_schema_id.into(),
          "protocol": protocol.into(),
          "issuer": issuer.into(),
          "issuerDid": issuer_did.into(),
          "issuerKey": issuer_key.into(),
          "issuerCertificate": issuer_certificate.into(),
          "claimValues": claims
        });

        if let Some(profile) = profile {
            body["profile"] = profile.into();
        }

        self.client.post("/api/credential/v1", body).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn list(
        &self,
        page: u64,
        size: u64,
        organisation_id: &impl Display,
        filters: Filters<'_>,
        include: Option<Vec<CredentialListIncludeEntityTypeEnum>>,
    ) -> Response {
        let mut url = format!(
            "/api/credential/v1?page={page}&pageSize={size}&organisationId={organisation_id}"
        );

        if let Some(name) = filters.name {
            url += &format!("&name={name}")
        }
        if let Some(search_text) = filters.search_text {
            url += &format!("&searchText={search_text}")
        }
        url += &filters
            .profiles
            .into_iter()
            .flatten()
            .fold(String::new(), |url, search_type| {
                url + &format!("&profiles[]={search_type}")
            });

        url += &filters
            .search_type
            .into_iter()
            .flatten()
            .fold(String::new(), |url, search_type| {
                url + &format!("&searchType[]={search_type}")
            });

        url += &filters
            .roles
            .into_iter()
            .flatten()
            .fold(String::new(), |url, role| url + &format!("&roles[]={role}"));

        url += &filters
            .ids
            .into_iter()
            .flatten()
            .fold(String::new(), |url, id| url + &format!("&ids[]={id}"));

        url += &filters
            .issuers
            .into_iter()
            .flatten()
            .fold(String::new(), |url, issuer| {
                url + &format!("&issuers[]={issuer}")
            });

        url += &filters
            .states
            .into_iter()
            .flatten()
            .fold(String::new(), |url, state| {
                url + &format!("&states[]={state}")
            });

        url += &filters.credential_schema_ids.into_iter().flatten().fold(
            String::new(),
            |url, credential_schema_id| {
                url + &format!("&credentialSchemaIds[]={credential_schema_id}")
            },
        );

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
        if let Some(date) = filters.issuance_date_after {
            url += &format!("&{}", query_time_urlencoded("issuanceDateAfter", date));
        }
        if let Some(date) = filters.issuance_date_before {
            url += &format!("&{}", query_time_urlencoded("issuanceDateBefore", date));
        }
        if let Some(date) = filters.revocation_date_after {
            url += &format!("&{}", query_time_urlencoded("revocationDateAfter", date));
        }
        if let Some(date) = filters.revocation_date_before {
            url += &format!("&{}", query_time_urlencoded("revocationDateBefore", date));
        }

        if let Some(include) = include {
            for item in include {
                url += &format!("&include[]={item}")
            }
        }
        self.client.get(&url).await
    }

    pub async fn get(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}");
        self.client.get(&url).await
    }

    pub async fn delete(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}");
        self.client.delete(&url).await
    }

    pub async fn reactivate(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/reactivate");
        self.client.post(&url, None).await
    }

    pub async fn revoke(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/revoke");
        self.client.post(&url, None).await
    }

    pub async fn suspend(&self, id: &impl Display, suspend_end_date: Option<String>) -> Response {
        let url = format!("/api/credential/v1/{id}/suspend");
        let body = suspend_end_date
            .map(|suspend_end_date| {
                json!({
                  "suspendEndDate": suspend_end_date,
                })
            })
            .unwrap_or(json!({}));

        self.client.post(&url, body).await
    }

    pub async fn revocation_check(
        &self,
        credential_id: impl Into<Uuid>,
        force_refresh: Option<bool>,
    ) -> Response {
        let mut body = json!({
          "credentialIds": vec![credential_id.into()]
        });

        if let Some(force_refresh) = force_refresh {
            body["forceRefresh"] = json!(force_refresh);
        }

        self.client
            .post("/api/credential/v1/revocation-check", body)
            .await
    }

    pub async fn share(&self, id: &impl Display) -> Response {
        let url = format!("/api/credential/v1/{id}/share");
        self.client.post(&url, None).await
    }
}
