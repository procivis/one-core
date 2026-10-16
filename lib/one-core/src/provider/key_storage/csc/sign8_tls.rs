use async_trait::async_trait;
use one_crypto::utilities::generate_random_bytes;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use standardized_types::csc::HashAlgorithm;

use super::CredentialAuthorization;
use crate::clock::now_utc;
use crate::error::ContextWithErrorCode;
use crate::proto::csc::model::{AuthorizeTlsRequest, TokenRequest};
use crate::proto::csc::{CscClient, build_sign8_account_token};
use crate::provider::key_storage::error::KeyStorageError;
use crate::provider::key_storage::model::Features;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Sign8Tls {
    oauth_url: String,
    redirect_url: String,
    account_id: String,
    client_id: String,
    client_secret: SecretString,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateParams {
    credential_id: String,
}

#[async_trait]
impl CredentialAuthorization for Sign8Tls {
    fn features(&self) -> Vec<Features> {
        vec![Features::RequiresCredentialId]
    }

    /// SIGN8 has no service scope: the token is bound to the credential and a random hash.
    async fn authorize_lookup(
        &self,
        csc_client: &dyn CscClient,
        generate_params: serde_json::Value,
    ) -> Result<(String, Option<String>), KeyStorageError> {
        let GenerateParams { credential_id } = serde_json::from_value(generate_params)?;
        let random_hash = generate_random_bytes::<32>();
        let token = self
            .fetch_access_token(csc_client, &credential_id, &[random_hash.as_slice()])
            .await?;
        Ok((token, Some(credential_id)))
    }

    async fn authorize_signing(
        &self,
        csc_client: &dyn CscClient,
        credential_id: &str,
        hash: &[u8],
    ) -> Result<String, KeyStorageError> {
        self.fetch_access_token(csc_client, credential_id, &[hash])
            .await
    }

    async fn release(&self, csc_client: &dyn CscClient, access_token: &str) {
        csc_client
            .revoke_access_token(
                &self.oauth_url,
                access_token,
                &self.client_id,
                self.client_secret.expose_secret(),
            )
            .await;
    }
}

impl Sign8Tls {
    async fn fetch_access_token(
        &self,
        csc_client: &dyn CscClient,
        credential_id: &str,
        hashes: &[&[u8]],
    ) -> Result<String, KeyStorageError> {
        let Self {
            oauth_url,
            redirect_url,
            account_id,
            client_id,
            client_secret,
        } = self;
        let account_token =
            build_sign8_account_token(account_id, client_id, client_secret, now_utc()).await?;
        let authorization = csc_client
            .authorize_tls(AuthorizeTlsRequest {
                oauth_url,
                client_id,
                redirect_uri: redirect_url,
                account_token: &account_token,
                credential_id,
                hashes,
                hash_algorithm: HashAlgorithm::Sha256,
            })
            .await
            .error_while("fetching authorization code")?;
        let token = csc_client
            .exchange_code(TokenRequest {
                oauth_url,
                code: &authorization.code,
                client_id,
                client_secret: client_secret.expose_secret(),
                redirect_uri: redirect_url,
                code_verifier: &authorization.code_verifier,
            })
            .await
            .error_while("exchanging code for token")?;
        Ok(token.access_token)
    }
}
