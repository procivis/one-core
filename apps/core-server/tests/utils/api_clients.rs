use std::sync::OnceLock;

use jsonld::JsonLdApi;
use serde::de::DeserializeOwned;
use serde_json::Value;

use self::config::ConfigApi;
use self::credential_schemas::CredentialSchemasApi;
use self::credentials::CredentialsApi;
use self::did_resolvers::DidResolversApi;
use self::dids::DidsApi;
use self::histories::HistoriesApi;
use self::interactions::InteractionsApi;
use self::keys::KeysApi;
use self::organisations::OrganisationsApi;
use self::proof_schemas::ProofSchemasApi;
use self::proofs::ProofsApi;
use self::ssi::SSIApi;
use self::tasks::TasksApi;
use self::trust_anchors::TrustAnchorsApi;
use self::trust_entity::TrustEntitiesApi;
use super::field_match::FieldHelpers;

pub mod config;
pub mod credential_schemas;
pub mod credentials;
pub mod did_resolvers;
pub mod dids;
pub mod histories;
pub mod interactions;
pub mod jsonld;
pub mod keys;
pub mod organisations;
pub mod proof_schemas;
pub mod proofs;
pub mod ssi;
pub mod tasks;
pub mod trust_anchors;
pub mod trust_entity;

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

    pub async fn post_form(&self, url: &str, form: &[(&str, &str)]) -> Response {
        let url = format!("{}{url}", self.base_url);

        let resp = http_client()
            .post(url)
            .bearer_auth(&self.token)
            .form(form)
            .send()
            .await
            .unwrap();

        Response { resp }
    }

    pub async fn patch(&self, url: &str, body: impl Into<Option<Value>>) -> Response {
        let url = format!("{}{url}", self.base_url);

        let resp = http_client()
            .patch(url)
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

    pub async fn error_code(self) -> String {
        self.json_value().await["code"].parse()
    }
}

pub struct Client {
    pub organisations: OrganisationsApi,
    pub credentials: CredentialsApi,
    pub interactions: InteractionsApi,
    pub credential_schemas: CredentialSchemasApi,
    pub dids: DidsApi,
    pub histories: HistoriesApi,
    pub did_resolvers: DidResolversApi,
    pub keys: KeysApi,
    pub proof_schemas: ProofSchemasApi,
    pub proofs: ProofsApi,
    pub ssi: SSIApi,
    pub tasks: TasksApi,
    pub config: ConfigApi,
    pub trust_anchors: TrustAnchorsApi,
    pub trust_entities: TrustEntitiesApi,
    pub jsonld: JsonLdApi,
}

impl Client {
    pub fn new(base_url: String, token: String) -> Self {
        let client = HttpClient { base_url, token };

        Self {
            organisations: OrganisationsApi::new(client.clone()),
            credentials: CredentialsApi::new(client.clone()),
            interactions: InteractionsApi::new(client.clone()),
            credential_schemas: CredentialSchemasApi::new(client.clone()),
            dids: DidsApi::new(client.clone()),
            histories: HistoriesApi::new(client.clone()),
            did_resolvers: DidResolversApi::new(client.clone()),
            keys: KeysApi::new(client.clone()),
            proof_schemas: ProofSchemasApi::new(client.clone()),
            proofs: ProofsApi::new(client.clone()),
            ssi: SSIApi::new(client.clone()),
            tasks: TasksApi::new(client.clone()),
            config: ConfigApi::new(client.clone()),
            trust_anchors: TrustAnchorsApi::new(client.clone()),
            trust_entities: TrustEntitiesApi::new(client.clone()),
            jsonld: JsonLdApi::new(client),
        }
    }
}
