use similar_asserts::assert_eq;
use standardized_types::jwk::PrivateJwkEc;

use super::*;

#[test]
fn test_public_key_representations() {
    let jwk = PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_owned(),
        x: "CQKO9r8IF7mEYhZImiOoLqw70WYLAohqT3JkomZW3x4".to_owned(),
        y: Some("khCene-e-_GAeE8N-aWUUucY_dVGRGCqpQmVhPwDHUM".to_owned()),
    });

    let key = Ecdsa.parse_jwk(&jwk).unwrap();

    assert_eq!(
        key.public_key_as_raw(),
        vec![
            3, 9, 2, 142, 246, 191, 8, 23, 185, 132, 98, 22, 72, 154, 35, 168, 46, 172, 59, 209,
            102, 11, 2, 136, 106, 79, 114, 100, 162, 102, 86, 223, 30
        ]
    );

    assert_eq!(
        key.public_key_as_der().unwrap(),
        vec![
            48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3, 1, 7,
            3, 66, 0, 4, 9, 2, 142, 246, 191, 8, 23, 185, 132, 98, 22, 72, 154, 35, 168, 46, 172,
            59, 209, 102, 11, 2, 136, 106, 79, 114, 100, 162, 102, 86, 223, 30, 146, 16, 158, 157,
            239, 158, 251, 241, 128, 120, 79, 13, 249, 165, 148, 82, 231, 24, 253, 213, 70, 68, 96,
            170, 165, 9, 149, 132, 252, 3, 29, 67,
        ]
    );

    assert_eq!(
        key.public_key_as_multibase().unwrap(),
        "zDnaeiGTMBcApuCYkKHJF6QdoRD9vRhVtS82gwLERpGJjj3N5"
    );

    assert_eq!(key.public_key_as_jwk().unwrap(), jwk);

    assert_eq!(
        key.public_key_as_cose().unwrap(),
        CoseKey {
            kty: iana::KeyType::EC2.into(),
            key_id: Default::default(),
            alg: None,
            key_ops: Default::default(),
            base_iv: Default::default(),
            params: vec![
                (
                    coset::Label::Int(iana::Ec2KeyParameter::Crv as i64),
                    ciborium::Value::from(iana::EllipticCurve::P_256 as u64),
                ),
                (
                    coset::Label::Int(iana::Ec2KeyParameter::X as i64),
                    ciborium::Value::Bytes(vec![
                        9, 2, 142, 246, 191, 8, 23, 185, 132, 98, 22, 72, 154, 35, 168, 46, 172,
                        59, 209, 102, 11, 2, 136, 106, 79, 114, 100, 162, 102, 86, 223, 30,
                    ])
                ),
                (
                    coset::Label::Int(iana::Ec2KeyParameter::Y as i64),
                    ciborium::Value::Bytes(vec![
                        146, 16, 158, 157, 239, 158, 251, 241, 128, 120, 79, 13, 249, 165, 148, 82,
                        231, 24, 253, 213, 70, 68, 96, 170, 165, 9, 149, 132, 252, 3, 29, 67,
                    ])
                ),
            ]
        }
    );
}

#[tokio::test]
async fn test_generate_key() {
    let es256_alg = Ecdsa {};
    let key = es256_alg.generate_key().unwrap();

    let jwk = key.key.key_agreement().unwrap().public().as_jwk().unwrap();
    let PublicJwk::Ec(jwk) = jwk else {
        panic!("invalid key type");
    };
    assert_eq!("P-256", jwk.crv);

    let recipient_jwk = PublicJwk::Ec(PublicJwkEc {
        alg: None,
        r#use: None,
        kid: None,
        crv: "P-256".to_string(),
        x: "KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo".to_string(),
        y: Some("d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU".to_string()),
    });

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

    let private_jwk = PrivateJwk::Ec(PrivateJwkEc {
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

    let private_jwk = PrivateJwk::Ec(PrivateJwkEc {
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
    assert!(matches!(result, Err(KeyAlgorithmError::NotSupported(msg)) if msg == "crv P-512"));
}

#[test]
fn test_parse_cose() {
    // given
    let cose_key = CoseKey {
        kty: iana::KeyType::EC2.into(),
        params: vec![
            (
                coset::Label::Int(iana::Ec2KeyParameter::Crv.to_i64()),
                ciborium::Value::from(iana::EllipticCurve::P_256 as u64),
            ),
            (
                coset::Label::Int(iana::Ec2KeyParameter::X.to_i64()),
                ciborium::Value::Bytes(
                    hex::decode("5A88D182BCE5F42EFA59943F33359D2E8A968FF289D93E5FA444B624343167FE")
                        .unwrap(),
                ),
            ),
            (
                coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64()),
                ciborium::Value::Bytes(
                    hex::decode("B16E8CF858DDC7690407BA61D4C338237A8CFCF3DE6AA672FC60A557AA32FC67")
                        .unwrap(),
                ),
            ),
        ],
        ..Default::default()
    };

    // when
    let key_handle = Ecdsa.parse_cose(&cose_key).unwrap();

    // then
    assert_eq!(
        key_handle.public_key_as_multibase().unwrap(),
        "zDnaeokh7UgnA8VdiHDjK67m68a4yCw13txKjnz3KjdjipE13"
    );
}
