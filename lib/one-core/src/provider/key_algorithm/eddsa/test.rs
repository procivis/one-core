use similar_asserts::assert_eq;

use super::*;
use crate::model::key::{PrivateKeyJwkEllipticData, PublicKeyJwkEllipticData};

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
        r#use: None,
        kid: None,
        crv: "Ed25519".to_owned(),
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
        y: None,
    });

    assert_eq!(
        vec![
            155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248,
            76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
        ],
        Eddsa.parse_jwk(&jwk).unwrap().public_key_as_raw()
    )
}

#[tokio::test]
async fn test_generate_ed25519() {
    let eddsa = Eddsa {};
    let key = eddsa.generate_key().unwrap();

    let recipient_jwk = RemoteJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: "0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM".to_string(),
        y: None,
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
    assert_eq!("OKP", remote_jwk.kty);
    assert_eq!("X25519", remote_jwk.crv);
}

#[tokio::test]
async fn test_parse_jwk() {
    // given
    let eddsa = Eddsa;

    let public_jwk = PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
        r#use: None,
        kid: None,
        crv: "Ed25519".to_owned(),
        x: "RpkY0z00AgocisOQlvpc-yHuaR2FvQ4l9MSvijLKqSc".to_string(),
        y: None,
    });

    let private_jwk = PrivateKeyJwk::Okp(PrivateKeyJwkEllipticData {
        r#use: None,
        kid: None,
        crv: "Ed25519".to_string(),
        x: "RpkY0z00AgocisOQlvpc-yHuaR2FvQ4l9MSvijLKqSc".to_string(),
        y: None,
        d: "6mkUGcU9amJ05SWpKpcsh4hHI-FcoWpvpoB7LIDzkX0".into(),
    });

    // when
    let public_key = Eddsa.parse_jwk(&public_jwk).unwrap().public_key_as_raw();
    let generated_key = eddsa.parse_private_jwk(private_jwk).unwrap();

    // then
    assert_eq!(public_key, generated_key.public);
    assert_eq!(
        vec![
            234, 105, 20, 25, 197, 61, 106, 98, 116, 229, 37, 169, 42, 151, 44, 135, 136, 71, 35,
            225, 92, 161, 106, 111, 166, 128, 123, 44, 128, 243, 145, 125, 70, 153, 24, 211, 61,
            52, 2, 10, 28, 138, 195, 144, 150, 250, 92, 251, 33, 238, 105, 29, 133, 189, 14, 37,
            244, 196, 175, 138, 50, 202, 169, 39
        ],
        generated_key.private.expose_secret()
    );
}

#[tokio::test]
async fn test_parse_jwk_invalid_crv() {
    // given
    let eddsa = Eddsa;

    let private_jwk = PrivateKeyJwk::Okp(PrivateKeyJwkEllipticData {
        r#use: None,
        kid: None,
        crv: "P-512".to_string(),
        x: "invalid".to_string(),
        y: Some("invalid".to_string()),
        d: "invalid".into(),
    });

    // when
    let result = eddsa.parse_private_jwk(private_jwk);

    // then
    assert!(
        matches!(result, Err(KeyAlgorithmError::Failed(msg)) if msg == "unsupported crv P-512")
    );
}
