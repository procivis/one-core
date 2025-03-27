use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_crypto::signer::ecdsa::ECDSASigner;
use one_crypto::signer::eddsa::EDDSASigner;

use crate::model::key::{PublicKeyJwk, PublicKeyJwkEllipticData};
use crate::provider::key_algorithm::key::KeyHandleError;

pub fn eddsa_public_key_as_jwk(
    public_key: &[u8],
    curve: &str,
    r#use: Option<String>,
) -> Result<PublicKeyJwk, KeyHandleError> {
    Ok(PublicKeyJwk::Okp(PublicKeyJwkEllipticData {
        r#use,
        kid: None,
        crv: curve.to_string(),
        x: Base64UrlSafeNoPadding::encode_to_string(public_key)
            .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
        y: None,
    }))
}

pub fn eddsa_public_key_as_multibase(public_key: &[u8]) -> Result<String, KeyHandleError> {
    let codec = &[0xed, 0x1];
    let key = EDDSASigner::check_public_key(public_key)
        .map_err(|e| KeyHandleError::EncodingMultibase(e.to_string()))?;
    let data = [codec, key.as_slice()].concat();
    Ok(format!("z{}", bs58::encode(data).into_string()))
}

pub fn ecdsa_public_key_as_jwk(
    public_key: &[u8],
    r#use: Option<String>,
) -> Result<PublicKeyJwk, KeyHandleError> {
    let (x, y) =
        ECDSASigner::get_public_key_coordinates(public_key).map_err(KeyHandleError::Signer)?;
    Ok(PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
        r#use,
        kid: None,
        crv: "P-256".to_string(),
        x: Base64UrlSafeNoPadding::encode_to_string(x)
            .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
        y: Some(
            Base64UrlSafeNoPadding::encode_to_string(y)
                .map_err(|e| KeyHandleError::EncodingJwk(e.to_string()))?,
        ),
    }))
}

pub fn ecdsa_public_key_as_multibase(public_key: &[u8]) -> Result<String, KeyHandleError> {
    let codec = &[0x80, 0x24];
    let key = ECDSASigner::parse_public_key(public_key, true)
        .map_err(|e| KeyHandleError::EncodingMultibase(e.to_string()))?;
    let data = [codec, key.as_slice()].concat();
    Ok(format!("z{}", bs58::encode(data).into_string()))
}
