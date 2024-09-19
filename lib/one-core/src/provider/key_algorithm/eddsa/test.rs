use super::*;

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
        r#use: None,
        crv: "Ed25519".to_owned(),
        x: "m7AE5UQdjLuCOnZHB1gCFfo2uvhM6W_4xFmpJK02r7s".to_owned(),
        y: None,
    });

    let alg = Eddsa::new(EddsaParams {
        algorithm: Algorithm::Ed25519,
    });

    assert_eq!(
        vec![
            155, 176, 4, 229, 68, 29, 140, 187, 130, 58, 118, 71, 7, 88, 2, 21, 250, 54, 186, 248,
            76, 233, 111, 248, 196, 89, 169, 36, 173, 54, 175, 187,
        ],
        alg.jwk_to_bytes(&jwk).unwrap()
    )
}
