use super::*;
use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};

struct TestData {
    jwk: PublicKeyJwk,
    serialized: Vec<u8>,
}
fn get_test_key() -> TestData {
    TestData {
        jwk: PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
            r#use: None,
            kid: None,
            crv: "Bls12381G2".to_owned(),
            x: "Ajs8lstTgoTgXMF6QXdyh3m8k2ixxURGYLMaYylVK_x0F8HhE8zk0YWiGV3CHwpQEa2sH4PBZLaYCn8se-1clmCORDsKxbbw3Js_Alu4OmkV9gmbJsy1YF2rt7Vxzs6S".to_owned(),
            y: Some("BVkkrVEib-P_FMPHNtqxJymP3pV-H8fCdvPkoWInpFfM9tViyqD8JAmwDf64zU2hBV_vvCQ632ScAooEExXuz1IeQH9D2o-uY_dAjZ37YHuRMEyzh8Tq-90JHQvicOqx".to_owned()),
        }),
        serialized: vec![
            130, 59, 60, 150, 203, 83, 130, 132, 224, 92, 193, 122, 65, 119, 114, 135, 121, 188,
            147, 104, 177, 197, 68, 70, 96, 179, 26, 99, 41, 85, 43, 252, 116, 23, 193, 225, 19,
            204, 228, 209, 133, 162, 25, 93, 194, 31, 10, 80, 17, 173, 172, 31, 131, 193, 100, 182,
            152, 10, 127, 44, 123, 237, 92, 150, 96, 142, 68, 59, 10, 197, 182, 240, 220, 155, 63,
            2, 91, 184, 58, 105, 21, 246, 9, 155, 38, 204, 181, 96, 93, 171, 183, 181, 113, 206,
            206, 146
        ]
    }
}

#[test]
fn test_jwk_to_bytes() {
    let TestData { jwk, serialized } = get_test_key();
    let alg = BBS;
    assert_eq!(serialized, alg.jwk_to_bytes(&jwk).unwrap())
}

#[test]
fn test_bytes_to_jwk() {
    let TestData { jwk, serialized } = get_test_key();
    let alg = BBS;
    assert_eq!(alg.bytes_to_jwk(&serialized, None).unwrap(), jwk)
}
