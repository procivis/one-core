use super::*;
use crate::model::key::PublicKeyJwkEllipticData;

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
