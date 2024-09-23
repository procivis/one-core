use super::*;

#[test]
fn test_jwk_to_bytes() {
    let jwk = PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
        r#use: None,
        crv: "P-256".to_owned(),
        x: "CQKO9r8IF7mEYhZImiOoLqw70WYLAohqT3JkomZW3x4".to_owned(),
        y: Some("khCene-e-_GAeE8N-aWUUucY_dVGRGCqpQmVhPwDHUM".to_owned()),
    });

    let alg = Es256::new(Es256Params {
        algorithm: Algorithm::Es256,
    });

    assert_eq!(
        vec![
            3, 9, 2, 142, 246, 191, 8, 23, 185, 132, 98, 22, 72, 154, 35, 168, 46, 172, 59, 209,
            102, 11, 2, 136, 106, 79, 114, 100, 162, 102, 86, 223, 30
        ],
        alg.jwk_to_bytes(&jwk).unwrap()
    )
}
