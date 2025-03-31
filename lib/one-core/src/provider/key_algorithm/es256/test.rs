use super::*;
use crate::model::key::PublicKeyJwkEllipticData;

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
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
        Es256.parse_jwk(&jwk).unwrap().public_key_as_raw()
    )
}

#[tokio::test]
async fn test_generate_key() {
    let es256_alg = Es256 {};
    let key = es256_alg.generate_key().unwrap();

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

    let remote_jwk = key.key.key_agreement().unwrap().public().as_jwk().unwrap();
    assert_eq!("EC", remote_jwk.kty);
    assert_eq!("P-256", remote_jwk.crv);
}
