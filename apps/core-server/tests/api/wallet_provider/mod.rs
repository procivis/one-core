use std::ops::Add;
use std::str::FromStr;

use one_core::model::identifier::{IdentifierState, IdentifierType};
use one_core::model::organisation::Organisation;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::provider::key_algorithm::model::GeneratedKey;
use one_core::util::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::util::jwt::model::JWTPayload;
use one_core::util::jwt::{Jwt, JwtPublicKeyInfo};
use one_crypto::encryption::encrypt_data;
use secrecy::SecretSlice;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::{TestingIdentifierParams, TestingKeyParams};
use crate::utils::context::TestContext;

mod activate_wallet_unit;
mod refresh_wallet_unit;
mod register_wallet_unit;

async fn create_key_possession_proof(key: &GeneratedKey, aud: String) -> String {
    let now = OffsetDateTime::now_utc();
    let jwt = Jwt::new(
        "JWT".to_string(),
        "ES256".to_string(),
        None,
        Some(JwtPublicKeyInfo::Jwk(
            key.key.public_key_as_jwk().unwrap().into(),
        )),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now.add(Duration::hours(10))),
            invalid_before: Some(now),
            audience: Some(vec![aud]),
            custom: (),
            ..Default::default()
        },
    );

    let jwt_header_json = serde_json::to_string(&jwt.header).unwrap();
    let payload_json = serde_json::to_string(&jwt.payload).unwrap();
    let mut token = format!(
        "{}.{}",
        string_to_b64url_string(&jwt_header_json).unwrap(),
        string_to_b64url_string(&payload_json).unwrap(),
    );

    let signature = key.key.sign(token.as_bytes()).await.unwrap();
    let signature_encoded = bin_to_b64url_string(&signature).unwrap();

    token.push('.');
    token.push_str(&signature_encoded);
    token
}

async fn create_wallet_unit_attestation_issuer_identifier(
    context: &TestContext,
    org: &Organisation,
) {
    let issuer_key_pair = Ecdsa.generate_key().unwrap();
    let internal_storage_encryption_key = SecretSlice::from(
        hex::decode("93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e").unwrap(), // has to match config keyStorage.INTERNAL.params.private.encryption
    );
    let issuer_private_key_reference =
        encrypt_data(&issuer_key_pair.private, &internal_storage_encryption_key).unwrap();

    let issuer_key = context
        .db
        .keys
        .create(
            org,
            TestingKeyParams {
                key_type: Some("ECDSA".to_string()),
                storage_type: Some("INTERNAL".to_string()),
                public_key: Some(issuer_key_pair.public.clone()),
                key_reference: Some(issuer_private_key_reference),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .identifiers
        .create(
            org,
            TestingIdentifierParams {
                id: Some(
                    Uuid::from_str("dea4b53c-4d0e-4d93-ae81-2c996996a2fe") // has to match config walletProvider.PROCIVIS_ONE.params.public.issuerIdentifier
                        .unwrap()
                        .into(),
                ),
                r#type: Some(IdentifierType::Key),
                state: Some(IdentifierState::Active),
                key: Some(issuer_key),
                is_remote: Some(false),
                ..Default::default()
            },
        )
        .await;
}
