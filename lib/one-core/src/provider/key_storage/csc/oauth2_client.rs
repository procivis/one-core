use async_trait::async_trait;
use ct_codecs::{Base64, Encoder};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use standardized_types::csc::{CredentialAuthorizationDetails, DocumentDigest, HashAlgorithm};
use time::Duration;
use uuid::Uuid;

use super::CredentialAuthorization;
use crate::clock::now_utc;
use crate::error::ContextWithErrorCode;
use crate::proto::csc::CscClient;
use crate::proto::csc::model::ClientCredentialsRequest;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::jwt::rsa::RS256Signer;
use crate::provider::key_storage::error::KeyStorageError;

const CLIENT_ASSERTION_VALIDITY: Duration = Duration::minutes(5);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Params {
    token_url: String,
    client_id: String,
    signer_client_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateParams {
    credential_id: Option<String>,
}

pub(super) struct Oauth2Client {
    params: Params,
    private_key: SecretString,
}

#[async_trait]
impl CredentialAuthorization for Oauth2Client {
    async fn authorize_lookup(
        &self,
        csc_client: &dyn CscClient,
        generate_params: serde_json::Value,
    ) -> Result<(String, Option<String>), KeyStorageError> {
        let GenerateParams { credential_id } = serde_json::from_value(generate_params)?;
        let token = self
            .access_token(csc_client, &self.params.client_id, "service", None)
            .await?;
        Ok((token, credential_id))
    }

    async fn authorize_signing(
        &self,
        csc_client: &dyn CscClient,
        credential_id: &str,
        hash: &[u8],
    ) -> Result<String, KeyStorageError> {
        let authorization_details = serde_json::to_string(&[CredentialAuthorizationDetails {
            r#type: "credential".to_string(),
            credential_id: credential_id.to_string(),
            hash_algorithm: HashAlgorithm::Sha256,
            document_digests: vec![DocumentDigest {
                hash: Base64::encode_to_string(hash)
                    .map_err(|err| KeyStorageError::Failed(err.to_string()))?,
                label: "document".to_string(),
            }],
        }])?;
        self.access_token(
            csc_client,
            &self.params.signer_client_id,
            "credential",
            Some(&authorization_details),
        )
        .await
    }
}

impl Oauth2Client {
    pub(super) fn new(params: Params, private_key: SecretString) -> Self {
        Self {
            params,
            private_key,
        }
    }

    async fn client_assertion(&self, client_id: &str) -> Result<String, KeyStorageError> {
        let signer = RS256Signer::from_pem(self.private_key.expose_secret())?;
        let now = now_utc();
        let payload = JWTPayload::<()> {
            issuer: Some(client_id.to_string()),
            subject: Some(client_id.to_string()),
            audience: Some(vec![self.params.token_url.clone()]),
            jwt_id: Some(Uuid::new_v4().to_string()),
            issued_at: Some(now),
            expires_at: Some(now + CLIENT_ASSERTION_VALIDITY),
            ..Default::default()
        };
        Jwt::new("JWT".to_string(), "RS256".to_string(), None, None, payload)
            .tokenize(Some(&signer))
            .await
            .error_while("creating client assertion")
            .map_err(Into::into)
    }

    async fn access_token(
        &self,
        csc_client: &dyn CscClient,
        client_id: &str,
        scope: &str,
        authorization_details: Option<&str>,
    ) -> Result<String, KeyStorageError> {
        let client_assertion = self.client_assertion(client_id).await?;
        csc_client
            .client_credentials_token(ClientCredentialsRequest {
                token_url: &self.params.token_url,
                client_id,
                client_assertion: &client_assertion,
                scope,
                authorization_details,
            })
            .await
            .error_while("requesting access token")
            .map_err(Into::into)
    }
}
