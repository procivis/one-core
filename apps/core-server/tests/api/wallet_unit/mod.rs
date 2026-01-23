use std::ops::Add;

use one_core::proto::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_core::proto::jwt::model::{JWTPayload, ProofOfPossessionKey};
use one_core::proto::jwt::{Jwt, JwtPublicKeyInfo};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use standardized_types::jwk::PublicJwk;
use time::{Duration, OffsetDateTime};

pub mod get_wallet_unit_tests;
pub mod holder_get_wallet_unit;
pub mod holder_register_wallet_unit;
pub mod holder_wallet_unit_status_tests;
pub mod list_wallet_unit_tests;
pub mod revoke_wallet_unit_tests;

async fn create_wallet_unit_attestation(wallet_key: PublicJwk, base_url: String) -> String {
    let provider_key = Ecdsa.generate_key().unwrap();
    let now = OffsetDateTime::now_utc();
    let jwt = Jwt::<()>::new(
        "oauth-client-attestation+jwt".to_string(),
        "ES256".to_string(),
        None,
        Some(JwtPublicKeyInfo::Jwk(
            provider_key.key.public_key_as_jwk().unwrap(),
        )),
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now.add(Duration::seconds(100))),
            invalid_before: Some(now),
            issuer: Some(base_url.clone()),
            subject: Some(format!("{base_url}/PROCIVIS_ONE")),
            proof_of_possession_key: Some(ProofOfPossessionKey {
                key_id: None,
                jwk: wallet_key,
            }),
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

    let signature = provider_key.key.sign(token.as_bytes()).await.unwrap();
    let signature_encoded = bin_to_b64url_string(&signature).unwrap();

    token.push('.');
    token.push_str(&signature_encoded);
    token
}
