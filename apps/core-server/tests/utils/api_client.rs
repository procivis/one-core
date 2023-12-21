use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use uuid::Uuid;

pub fn client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::ClientBuilder::new().build().unwrap())
}

pub struct Response {
    resp: reqwest::Response,
}

impl Response {
    pub fn status(&self) -> u16 {
        self.resp.status().into()
    }

    pub async fn json<T: DeserializeOwned>(self) -> T {
        let full = self.resp.bytes().await.unwrap();
        serde_json::from_slice(&full).unwrap()
    }

    pub async fn json_value(self) -> Value {
        self.json().await
    }
}

pub struct Client {
    base_url: String,
    auth_token: String,
}

impl Client {
    pub fn new(base_url: String, auth_token: String) -> Self {
        Self {
            base_url,
            auth_token,
        }
    }

    pub async fn delete_credential(&self, id: impl std::fmt::Display) -> Response {
        let url = format!("{}/api/credential/v1/{id}", self.base_url);

        let resp = client()
            .delete(url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn list_credentials(
        &self,
        page: usize,
        page_size: usize,
        organisation_id: impl std::fmt::Display,
    ) -> Response {
        let url = format!("{}/api/credential/v1?page={page}&pageSize={page_size}&organisationId={organisation_id}", self.base_url);

        let resp = client()
            .get(url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn create_organisation(&self, id: impl Into<Option<Uuid>>) -> Response {
        let url = format!("{}/api/organisation/v1", self.base_url);
        let body = match id.into() {
            Some(id) => json!({"id": id}),
            None => json!({}),
        };

        let resp = client()
            .post(url)
            .bearer_auth(&self.auth_token)
            .json(&body)
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn list_organisations(&self) -> Response {
        let url = format!("{}/api/organisation/v1", self.base_url);

        let resp = client()
            .get(url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn get_organisation(&self, id: impl Into<Uuid>) -> Response {
        let url = format!("{}/api/organisation/v1/{}", self.base_url, id.into());

        let resp = client()
            .get(url)
            .bearer_auth(&self.auth_token)
            .send()
            .await
            .unwrap();

        Response { resp }
    }
}
