use super::*;

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwkDTO::Mlwe(PublicKeyJwkMlweDataDTO {
        r#use: None,
        alg: "CRYDI3".to_owned(),
        // Fake key just to prove the flow.
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
    });

    let alg = MlDsa::new(MlDsaParams {
        algorithm: Algorithm::Crydi3,
    });

    assert_eq!(
        vec![
            155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248,
            76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
        ],
        alg.jwk_to_bytes(&jwk).unwrap()
    )
}

#[test]
fn test_jwk_to_bytes_fail_wrong_variant() {
    let jwk = PublicKeyJwkDTO::Mlwe(PublicKeyJwkMlweDataDTO {
        r#use: None,
        alg: "CRYDI5".to_owned(), // Incorrect variant
        // Fake key just to prove the flow.
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
    });

    let alg = MlDsa::new(MlDsaParams {
        algorithm: Algorithm::Crydi3,
    });

    assert!(alg.jwk_to_bytes(&jwk).is_err());
}
