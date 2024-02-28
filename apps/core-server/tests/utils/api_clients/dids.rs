use std::fmt::Display;

use serde_json::json;
use shared_types::KeyId;
use uuid::Uuid;

use super::{HttpClient, Response};

pub struct DidsApi {
    client: HttpClient,
}

impl DidsApi {
    pub fn new(client: HttpClient) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        organisation_id: impl Into<Uuid>,
        keys: DidKeys,
        method: &str,
        name: &str,
    ) -> Response {
        let body = json!({
          "keys": {
            "assertionMethod": keys.assertion_method,
            "authentication": keys.authentication,
            "capabilityDelegation": keys.capability_delegation,
            "capabilityInvocation": keys.capability_invocation,
            "keyAgreement": keys.key_agreement,
          },
          "method": method,
          "name": name,
          "organisationId": organisation_id.into(),
          "params": {}
        });

        self.client.post("/api/did/v1", body).await
    }

    pub async fn list(
        &self,
        page: u64,
        page_size: u64,
        organisation_id: &impl Display,
        deactivated: bool,
        key_algorithms: Option<String>,
        key_roles: Option<String>,
    ) -> Response {
        let mut url = format!("/api/did/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}&deactivated={deactivated}");
        if key_algorithms.is_some() {
            let key_algorithms = key_algorithms.unwrap();
            url.push_str(&format!("&keyAlgorithms[]={key_algorithms}"));
        }
        if key_roles.is_some() {
            let key_roles = key_roles.unwrap();
            url.push_str(&format!("&keyRoles[]={key_roles}"));
        }
        self.client.get(&url).await
    }

    pub async fn get(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}");
        self.client.get(&url).await
    }

    pub async fn deactivate(&self, did_id: &impl Display) -> Response {
        let url = format!("/api/did/v1/{did_id}");
        let body = json!({
            "deactivated": true,
        });
        self.client.patch(&url, body).await
    }
}

pub struct DidKeys {
    pub assertion_method: Vec<KeyId>,
    pub authentication: Vec<KeyId>,
    pub capability_delegation: Vec<KeyId>,
    pub capability_invocation: Vec<KeyId>,
    pub key_agreement: Vec<KeyId>,
}

impl DidKeys {
    pub fn single(key: KeyId) -> Self {
        Self {
            assertion_method: vec![key],
            authentication: vec![key],
            capability_delegation: vec![key],
            capability_invocation: vec![key],
            key_agreement: vec![key],
        }
    }

    pub fn all(keys: Vec<KeyId>) -> Self {
        Self {
            assertion_method: keys.clone(),
            authentication: keys.clone(),
            capability_delegation: keys.clone(),
            capability_invocation: keys.clone(),
            key_agreement: keys,
        }
    }
}
