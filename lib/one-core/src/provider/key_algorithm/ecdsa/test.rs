use similar_asserts::assert_eq;

use super::*;
use crate::model::key::{PrivateKeyJwkEllipticData, PublicKeyJwkEllipticData};

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_owned(),
        x: "CQKO9r8IF7mEYhZImiOoLqw70WYLAohqT3JkomZW3x4".to_owned(),
        y: Some("khCene-e-_GAeE8N-aWUUucY_dVGRGCqpQmVhPwDHUM".to_owned()),
    });

    assert_eq!(
        vec![
            3, 9, 2, 142, 246, 191, 8, 23, 185, 132, 98, 22, 72, 154, 35, 168, 46, 172, 59, 209,
            102, 11, 2, 136, 106, 79, 114, 100, 162, 102, 86, 223, 30
        ],
        Ecdsa.parse_jwk(&jwk).unwrap().public_key_as_raw()
    )
}

#[tokio::test]
async fn test_generate_key() {
    let es256_alg = Ecdsa {};
    let key = es256_alg.generate_key().unwrap();

    let jwk = key.key.key_agreement().unwrap().public().as_jwk().unwrap();
    let PublicKeyJwk::Ec(jwk) = jwk else {
        panic!("invalid key type");
    };
    assert_eq!("P-256", jwk.crv);

    let recipient_jwk = RemoteJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: "KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo".to_string(),
        y: Some("d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU".to_string()),
    };

    // verify if it succeeds for given JWK
    let _shared_secret = key
        .key
        .key_agreement()
        .unwrap()
        .private()
        .unwrap()
        .shared_secret(&recipient_jwk)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_parse_jwk() {
    // given
    let es256_alg = Ecdsa {};

    let private_jwk = PrivateKeyJwk::Ec(PrivateKeyJwkEllipticData {
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "be8opzoClZYrfXhjnrcJCAtKSnipGcR7wp_SHbEZuL0".to_string(),
        y: Some("ujG_ulU9aDKrlt-HZ7HCMe5mRkf2Gjrj4i7kiNrHCuk".to_string()),
        d: "LDMUiLwkl70SGM9qtyLZ4dSvdjrVz6oGp_clYb3HVS4".into(),
    });

    // when
    let generated_key = es256_alg.parse_private_jwk(private_jwk).unwrap();

    // then
    assert_eq!(
        vec![
            3, 109, 239, 40, 167, 58, 2, 149, 150, 43, 125, 120, 99, 158, 183, 9, 8, 11, 74, 74,
            120, 169, 25, 196, 123, 194, 159, 210, 29, 177, 25, 184, 189,
        ],
        generated_key.public
    );
    assert_eq!(
        vec![
            44, 51, 20, 136, 188, 36, 151, 189, 18, 24, 207, 106, 183, 34, 217, 225, 212, 175, 118,
            58, 213, 207, 170, 6, 167, 247, 37, 97, 189, 199, 85, 46,
        ],
        generated_key.private.expose_secret()
    );
}

#[tokio::test]
async fn test_parse_jwk_invalid_crv() {
    // given
    let es256_alg = Ecdsa {};

    let private_jwk = PrivateKeyJwk::Ec(PrivateKeyJwkEllipticData {
        r#use: None,
        kid: None,
        crv: "P-512".to_string(),
        x: "invalid".to_string(),
        y: Some("invalid".to_string()),
        d: "invalid".into(),
    });

    // when
    let result = es256_alg.parse_private_jwk(private_jwk);

    // then
    assert!(
        matches!(result, Err(KeyAlgorithmError::Failed(msg)) if msg == "unsupported crv P-512")
    );
}
