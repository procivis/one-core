use super::*;

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwk::Mlwe(PublicKeyJwkMlweData {
        r#use: None,
        kid: None,
        alg: "CRYDI3".to_owned(),
        // Fake key just to prove the flow.
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
    });

    assert_eq!(
        vec![
            155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248,
            76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
        ],
        MlDsa.parse_jwk(&jwk).unwrap().public_key_as_raw()
    )
}

#[test]
fn test_jwk_to_bytes_fail_wrong_variant() {
    let jwk = PublicKeyJwk::Mlwe(PublicKeyJwkMlweData {
        r#use: None,
        kid: None,
        alg: "CRYDI5".to_owned(), // Incorrect variant
        // Fake key just to prove the flow.
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
    });

    assert!(MlDsa.parse_jwk(&jwk).is_err());
}
