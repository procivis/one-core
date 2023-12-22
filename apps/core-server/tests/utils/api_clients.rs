use std::sync::OnceLock;

use serde::de::DeserializeOwned;
use serde_json::Value;

use self::credentials::CredentialsApi;
use self::interactions::InteractionsApi;
use self::organisations::OrganisationsApi;

pub mod credentials;
pub mod interactions;
pub mod organisations;

pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| reqwest::ClientBuilder::new().build().unwrap())
}

#[derive(Clone)]
pub struct HttpClient {
    base_url: String,
    token: String,
}

impl HttpClient {
    pub async fn get(&self, url: &str) -> Response {
        let url = format!("{}{url}", self.base_url);

        let resp = http_client()
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn post(&self, url: &str, body: impl Into<Option<Value>>) -> Response {
        let url = format!("{}{url}", self.base_url);

        let resp = http_client()
            .post(url)
            .bearer_auth(&self.token)
            .json(&body.into())
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn delete(&self, url: &str) -> Response {
        let url = format!("{}{url}", self.base_url);

        let resp = http_client()
            .delete(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();

        Response { resp }
    }
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
    pub organisations: OrganisationsApi,
    pub credentials: CredentialsApi,
    pub interactions: InteractionsApi,
}

impl Client {
    pub fn new(base_url: String, token: String) -> Self {
        let client = HttpClient { base_url, token };

        Self {
            organisations: OrganisationsApi::new(client.clone()),
            credentials: CredentialsApi::new(client.clone()),
            interactions: InteractionsApi::new(client),
        }
    }
}
