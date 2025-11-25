use std::sync::OnceLock;

use headers::HeaderMap;
use jsonld::JsonLdApi;
use serde::de::DeserializeOwned;
use serde_json::Value;

use self::certificates::CertificatesApi;
use self::config::ConfigApi;
use self::credential_schemas::CredentialSchemasApi;
use self::credentials::CredentialsApi;
use self::did_resolvers::DidResolversApi;
use self::dids::DidsApi;
use self::histories::HistoriesApi;
use self::identifiers::IdentifiersApi;
use self::interactions::InteractionsApi;
use self::keys::KeysApi;
use self::organisations::OrganisationsApi;
use self::other::OtherApi;
use self::proof_schemas::ProofSchemasApi;
use self::proofs::ProofsApi;
use self::ssi::SSIApi;
use self::tasks::TasksApi;
use self::trust_anchors::TrustAnchorsApi;
use self::trust_entity::TrustEntitiesApi;
use self::wallet_units::WalletUnitsApi;
use super::field_match::FieldHelpers;
use crate::utils::api_clients::cache::CacheApi;
use crate::utils::api_clients::holder_wallet_unit::HolderWalletUnitsApi;
use crate::utils::api_clients::wallet_provider::WalletProviderApi;

mod cache;
pub mod certificates;
pub mod config;
pub mod credential_schemas;
pub mod credentials;
pub mod did_resolvers;
pub mod dids;
pub mod histories;
pub mod identifiers;
pub mod interactions;
pub mod jsonld;
pub mod keys;
pub mod organisations;
pub mod other;
pub mod proof_schemas;
pub mod proofs;
pub mod ssi;
pub mod tasks;
pub mod trust_anchors;
pub mod trust_entity;
pub mod wallet_units;

pub mod holder_wallet_unit;
pub mod wallet_provider;

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
        self.post_custom_bearer_auth(url, &self.token, body).await
    }

    pub async fn post_custom_bearer_auth(
        &self,
        url: &str,
        token: &str,
        body: impl Into<Option<Value>>,
    ) -> Response {
        let url = format!("{}{url}", self.base_url);

        let mut builder = http_client().post(url).bearer_auth(token);

        if let Some(body) = body.into() {
            builder = builder.json(&body);
        }

        let resp = builder.send().await.unwrap();

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

#[derive(Debug)]
pub struct Response {
    resp: reqwest::Response,
}

impl From<reqwest::Response> for Response {
    fn from(resp: reqwest::Response) -> Self {
        Self { resp }
    }
}

impl Response {
    pub fn status(&self) -> u16 {
        self.resp.status().into()
    }

    pub fn headers(&self) -> &HeaderMap {
        self.resp.headers()
    }

    pub async fn text(self) -> String {
        self.resp.text().await.unwrap()
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
    pub cache: CacheApi,
    pub trust_anchors: TrustAnchorsApi,
    pub trust_entities: TrustEntitiesApi,
    pub jsonld: JsonLdApi,
    pub other: OtherApi,
    pub identifiers: IdentifiersApi,
    pub certificates: CertificatesApi,
    pub wallet_provider: WalletProviderApi,
    pub wallet_units: WalletUnitsApi,
    pub holder_wallet_units: HolderWalletUnitsApi,
    pub base_url: String,
}

impl Client {
    pub fn new(base_url: String, token: String) -> Self {
        let client = HttpClient {
            base_url: base_url.clone(),
            token,
        };

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
            cache: CacheApi::new(client.clone()),
            trust_anchors: TrustAnchorsApi::new(client.clone()),
            trust_entities: TrustEntitiesApi::new(client.clone()),
            jsonld: JsonLdApi::new(client.clone()),
            other: OtherApi::new(client.clone()),
            identifiers: IdentifiersApi::new(client.clone()),
            certificates: CertificatesApi::new(client.clone()),
            wallet_provider: WalletProviderApi::new(client.clone()),
            wallet_units: WalletUnitsApi::new(client.clone()),
            holder_wallet_units: HolderWalletUnitsApi::new(client),
            base_url,
        }
    }
}
