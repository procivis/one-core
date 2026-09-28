use similar_asserts::assert_eq;
use standardized_types::jwk::PrivateJwkEc;

use super::*;

#[test]
fn test_public_key_representations() {
    let jwk = PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "Ed25519".to_owned(),
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
        y: None,
    });

    let key = Eddsa.parse_jwk(&jwk).unwrap();

    assert_eq!(
        key.public_key_as_raw(),
        vec![
            155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248,
            76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
        ],
    );

    assert_eq!(
        key.public_key_as_der().unwrap(),
        vec![
            48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 155, 176, 4, 229, 68, 29, 140, 187, 130,
            58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248, 76, 233, 111, 248, 196, 89, 169, 36, 173,
            54, 175, 187,
        ]
    );

    assert_eq!(
        key.public_key_as_multibase().unwrap(),
        "z6MkpvzunJyRHjLn6dWmrmCafhBa1MPK5eazFLyHzvNonGNN"
    );

    assert_eq!(key.public_key_as_jwk().unwrap(), jwk);

    assert_eq!(
        key.public_key_as_cose().unwrap(),
        CoseKey {
            kty: iana::KeyType::OKP.into(),
            key_id: Default::default(),
            alg: None,
            key_ops: Default::default(),
            base_iv: Default::default(),
            params: vec![
                (
                    coset::Label::Int(iana::Ec2KeyParameter::Crv as i64),
                    ciborium::Value::from(iana::EllipticCurve::Ed25519 as u64),
                ),
                (
                    coset::Label::Int(iana::Ec2KeyParameter::X as i64),
                    ciborium::Value::Bytes(vec![
                        155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250,
                        54, 186, 248, 76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
                    ])
                ),
            ]
        }
    );
}

#[tokio::test]
async fn test_generate_ed25519() {
    let eddsa = Eddsa {};
    let key = eddsa.generate_key().unwrap();

    let jwk = key.key.key_agreement().unwrap().public().as_jwk().unwrap();
    let PublicJwk::Okp(jwk) = jwk else {
        panic!("invalid key type");
    };
    assert_eq!("X25519", jwk.crv);
}

#[tokio::test]
async fn test_shared_secret_against_ed25519() {
    let key = Eddsa.generate_key().unwrap();

    let recipient_jwk = PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "Ed25519".to_string(),
        x: "0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM".to_string(),
        y: None,
    });

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
async fn test_shared_secret_against_x25519() {
    let key = Eddsa.generate_key().unwrap();

    let recipient_jwk = PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "X25519".to_string(),
        x: "SzTHbXw_wfwSvQumRdHmSTW7tGTDWNKIt7ABGS2E9kc".to_string(),
        y: None,
    });

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
async fn test_parse_jwk_eddsa() {
    // given
    let eddsa = Eddsa;

    let public_jwk = PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "Ed25519".to_owned(),
        x: "RpkY0z00AgocisOQlvpc-yHuaR2FvQ4l9MSvijLKqSc".to_string(),
        y: None,
    });

    let private_jwk = PrivateJwk::Okp(PrivateJwkEc {
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
async fn test_parse_jwk_x25519() {
    // given

    let public_jwk = PublicJwk::Okp(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "X25519".to_owned(),
        x: "SzTHbXw_wfwSvQumRdHmSTW7tGTDWNKIt7ABGS2E9kc".to_string(),
        y: None,
    });

    // when
    let public_key = Eddsa.parse_jwk(&public_jwk).unwrap();

    // then
    assert_eq!(
        public_key.public_key_as_raw(),
        vec![
            75, 52, 199, 109, 124, 63, 193, 252, 18, 189, 11, 166, 69, 209, 230, 73, 53, 187, 180,
            100, 195, 88, 210, 136, 183, 176, 1, 25, 45, 132, 246, 71
        ],
    );
    assert_eq!(
        public_key.public_key_as_multibase().unwrap(),
        "z6LSgjkRLLbm634tqaMMtrwmk1svFDVEeGX4ke25A8o72ter"
    );
}

#[tokio::test]
async fn test_check_multibase_conformity() {
    // examples from: https://w3c-ccg.github.io/did-key-spec/#ed25519-with-x25519
    const EDDSA_MULTIBASE: &str = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const X25519_MULTIBASE: &str = "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";

    let parsed_eddsa = Eddsa.parse_multibase(EDDSA_MULTIBASE).unwrap();

    assert_eq!(
        parsed_eddsa
            .key_agreement()
            .unwrap()
            .public()
            .as_multibase()
            .unwrap(),
        X25519_MULTIBASE
    );
}

#[tokio::test]
async fn test_parse_jwk_invalid_crv() {
    // given
    let eddsa = Eddsa;

    let private_jwk = PrivateJwk::Okp(PrivateJwkEc {
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
    assert!(matches!(result, Err(KeyAlgorithmError::NotSupported(msg)) if msg == "crv P-512"));
}

#[test]
fn test_parse_cose_ed25519() {
    // given
    let cose_key = CoseKey {
        kty: iana::KeyType::OKP.into(),
        params: vec![
            (
                coset::Label::Int(iana::Ec2KeyParameter::Crv.to_i64()),
                ciborium::Value::from(iana::EllipticCurve::Ed25519 as u64),
            ),
            (
                coset::Label::Int(iana::Ec2KeyParameter::X.to_i64()),
                ciborium::Value::Bytes(
                    hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                        .unwrap(),
                ),
            ),
        ],
        ..Default::default()
    };

    // when
    let key_handle = Eddsa.parse_cose(&cose_key).unwrap();

    // then
    assert_eq!(
        key_handle.public_key_as_multibase().unwrap(),
        "z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
    );
}

#[test]
fn test_parse_cose_x25519() {
    // given
    let cose_key = CoseKey {
        kty: iana::KeyType::OKP.into(),
        params: vec![
            (
                coset::Label::Int(iana::Ec2KeyParameter::Crv.to_i64()),
                ciborium::Value::from(iana::EllipticCurve::X25519 as u64),
            ),
            (
                coset::Label::Int(iana::Ec2KeyParameter::X.to_i64()),
                ciborium::Value::Bytes(
                    hex::decode("7bf2ab247345df19ed1d0335e23a3be189679f2af4b5fb27211bf4b0ea6c001c")
                        .unwrap(),
                ),
            ),
        ],
        ..Default::default()
    };

    // when
    let key_handle = Eddsa.parse_cose(&cose_key).unwrap();

    // then
    assert_eq!(
        key_handle.public_key_as_multibase().unwrap(),
        "z6LSk21vqjYr1tFcs55uEnympDnDEepCMXNdJ7PJYMGjGYbu"
    );
}
