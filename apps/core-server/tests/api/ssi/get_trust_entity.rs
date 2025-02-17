use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use one_core::model::did::{Did, KeyRole, RelatedKey};
use one_core::model::organisation::Organisation;
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use one_core::provider::credential_formatter::jwt::model::{JWTHeader, JWTPayload};
use one_core::provider::credential_formatter::jwt::Jwt;
use one_core::provider::credential_formatter::model::SignatureProvider;
use one_core::provider::did_method::key::KeyDidMethod;
use one_core::provider::did_method::DidMethod;
use one_core::provider::key_algorithm::es256::{Algorithm, Es256, Es256Params};
use one_core::provider::key_algorithm::provider::KeyAlgorithmProviderImpl;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_crypto::signer::es256::ES256Signer;
use one_crypto::{Signer, SignerError};
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::fixtures::{TestingDidParams, TestingKeyParams};
use crate::utils::api_clients::Client;
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_entity_by_did_success() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    let (did, token) = prepare_bearer_token(&context, &org).await;
    let jwt_token_client = Client::new(context.config.app.core_base_url.clone(), token);
    let trust_anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity_one = context
        .db
        .trust_entities
        .create(
            "entity",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            trust_anchor.clone(),
            did.clone(),
        )
        .await;

    // WHEN
    let resp = jwt_token_client
        .ssi
        .get_trust_entity_by_did_value(did.did.to_string())
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body["id"].assert_eq(&entity_one.id);
    body["trustAnchor"]["id"].assert_eq(&trust_anchor.id);
    body["did"]["id"].assert_eq(&did.id);
}

struct FakeEs256Signer {
    public_key: Vec<u8>,
    private_key: SecretSlice<u8>,
    key_id: String,
}

#[async_trait]
impl SignatureProvider for FakeEs256Signer {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        ES256Signer {}.sign(message, &self.public_key, &self.private_key)
    }

    fn get_key_id(&self) -> Option<String> {
        Some(self.key_id.clone())
    }

    fn get_key_type(&self) -> &str {
        "ES256"
    }

    fn jose_alg(&self) -> Option<String> {
        Some("ES256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }
}
async fn prepare_bearer_token(context: &TestContext, org: &Organisation) -> (Did, String) {
    let (private_key, public_key) = ES256Signer::generate_key_pair();

    let key = context
        .db
        .keys
        .create(
            org,
            TestingKeyParams {
                public_key: Some(public_key.clone()),
                key_type: Some("ES256".to_string()),
                ..Default::default()
            },
        )
        .await;

    let key_algorithm_provider =
        Arc::new(KeyAlgorithmProviderImpl::new(HashMap::from_iter(vec![(
            "ES256".to_owned(),
            Arc::new(Es256::new(Es256Params {
                algorithm: Algorithm::Es256,
            })) as Arc<dyn KeyAlgorithm>,
        )])));
    let did_method = KeyDidMethod::new(key_algorithm_provider.clone());
    let did_value = did_method
        .create(None, &None, Some(vec![key.clone()]))
        .await
        .unwrap();
    let did = context
        .db
        .dids
        .create(
            org,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key,
                }]),
                did: Some(did_value.clone()),
                ..Default::default()
            },
        )
        .await;

    let payload = JWTPayload {
        issuer: Some(did.did.to_string()),
        ..Default::default()
    };

    let key_id = did_method
        .resolve(&did_value)
        .await
        .unwrap()
        .verification_method[0]
        .id
        .clone();
    let signer = FakeEs256Signer {
        public_key,
        private_key,
        key_id: key_id.clone(),
    };
    let bearer_token = Jwt::<BearerTokenPayload> {
        header: JWTHeader {
            algorithm: "ES256".to_string(),
            key_id: Some(key_id),
            r#type: None,
            jwk: None,
            jwt: None,
            x5c: None,
        },
        payload,
    }
    .tokenize(Some(Box::new(signer)))
    .await
    .unwrap();

    (did, bearer_token)
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BearerTokenPayload {
    #[serde(with = "time::serde::timestamp")]
    pub timestamp: OffsetDateTime,
}

impl Default for BearerTokenPayload {
    fn default() -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
        }
    }
}
