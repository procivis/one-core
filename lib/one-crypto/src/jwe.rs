use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
use josekit::jwe::JweHeader;
use josekit::jwk::Jwk;

use crate::encryption::EncryptionError;
use crate::signer::eddsa::EDDSASigner;

pub struct Header {
    pub key_id: String,
    // apu param
    pub agreement_partyuinfo: String,
    // apv param
    pub agreement_partyvinfo: String,
}

pub struct RemoteJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

/// Construct JWE using AES256GCM encryption
pub fn build_jwe(
    payload: &[u8],
    header: Header,
    recipient_jwk: RemoteJwk,
) -> Result<String, EncryptionError> {
    let jwk = convert_jwk(recipient_jwk)?;
    let header = convert_header(header);

    let encrypter = EcdhEsJweAlgorithm::EcdhEs
        .encrypter_from_jwk(&jwk)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    josekit::jwe::serialize_compact(payload, &header, &encrypter)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))
}

fn convert_header(input: Header) -> JweHeader {
    let mut header = JweHeader::new();
    header.set_key_id(input.key_id);
    header.set_content_encryption("A256GCM".to_string());
    header.set_agreement_partyuinfo(input.agreement_partyuinfo);
    header.set_agreement_partyvinfo(input.agreement_partyvinfo);
    header
}

fn convert_jwk(input: RemoteJwk) -> Result<Jwk, EncryptionError> {
    match input.kty.as_str() {
        "EC" => {
            let mut jwk = Jwk::new("EC");
            jwk.set_curve(input.crv);
            jwk.set_parameter("x", Some(input.x.into()))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            jwk.set_parameter(
                "y",
                Some(
                    input
                        .y
                        .ok_or(EncryptionError::Crypto("Missing Y parameter".to_string()))?
                        .into(),
                ),
            )
            .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            Ok(jwk)
        }
        "OKP" => {
            let mut jwk = Jwk::new("OKP");
            jwk.set_curve(input.crv);
            jwk.set_parameter("x", Some(input.x.into()))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

            if let Some("Ed25519") = jwk.curve() {
                jwk = ed25519_into_x25519(jwk)?;
            }

            Ok(jwk)
        }
        _ => Err(EncryptionError::Crypto(format!(
            "Invalid key type: {}",
            input.kty
        ))),
    }
}

fn ed25519_into_x25519(mut jwk: Jwk) -> Result<Jwk, EncryptionError> {
    if let Some("Ed25519") = jwk.curve() {
        jwk.set_curve("X25519");

        if let Some(x) = jwk.parameter("x").and_then(|x| x.as_str()) {
            let key = Base64UrlSafeNoPadding::decode_to_vec(x, None)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = EDDSASigner::public_key_into_x25519(&key)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            jwk.set_parameter("x", Some(key.into()))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        }

        if let Some(d) = jwk.parameter("d").and_then(|d| d.as_str()) {
            let key = Base64UrlSafeNoPadding::decode_to_vec(d, None)
                .map(zeroize::Zeroizing::new)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = EDDSASigner::private_key_into_x25519(&key)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
            let key = Base64UrlSafeNoPadding::encode_to_string(key.as_slice())
                .map(zeroize::Zeroizing::new)
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

            let key =
                serde_json::to_value(key).map_err(|e| EncryptionError::Crypto(e.to_string()))?;

            jwk.set_parameter("d", Some(key))
                .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
        };
    }

    Ok(jwk)
}

pub fn extract_jwe_header(jwe: &str) -> Result<Header, EncryptionError> {
    let header_b64 = jwe
        .split('.')
        .next()
        .ok_or_else(|| EncryptionError::Crypto("Invalid JWE".to_string()))?;

    let header = Base64UrlSafeNoPadding::decode_to_vec(header_b64, None)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&header).map_err(|e| EncryptionError::Crypto(e.to_string()))?;
    let jwe_header =
        JweHeader::from_map(map).map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    let key_id = jwe_header
        .key_id()
        .ok_or_else(|| EncryptionError::Crypto("JWE header is missing key_id".to_string()))?
        .to_owned();

    let agreement_partyuinfo = jwe_header
        .agreement_partyuinfo()
        .ok_or_else(|| EncryptionError::Crypto("JWE header is missing apu".to_string()))?;
    let agreement_partyuinfo = String::from_utf8(agreement_partyuinfo)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    let agreement_partyvinfo = jwe_header
        .agreement_partyvinfo()
        .ok_or_else(|| EncryptionError::Crypto("JWE header is missing apu".to_string()))?;
    let agreement_partyvinfo = String::from_utf8(agreement_partyvinfo)
        .map_err(|e| EncryptionError::Crypto(e.to_string()))?;

    Ok(Header {
        key_id,
        agreement_partyuinfo,
        agreement_partyvinfo,
    })
}

pub fn decrypt_jwe_payload(jwe: &str, private_jwk: &str) -> Result<Vec<u8>, EncryptionError> {
    let mut jwk = josekit::jwk::Jwk::from_bytes(private_jwk.as_bytes())
        .map_err(|err| EncryptionError::Crypto(format!("Failed constructing JWK {err}")))?;

    if let Some("Ed25519") = jwk.curve() {
        jwk = ed25519_into_x25519(jwk)?;
    }

    let decrypter = EcdhEsJweAlgorithm::EcdhEs
        .decrypter_from_jwk(&jwk)
        .map_err(|err| {
            EncryptionError::Crypto(format!("Failed constructing EcdhEs decrypter: {err}"))
        })?;

    let (payload, _) = josekit::jwe::deserialize_compact(jwe, &decrypter)
        .map_err(|err| EncryptionError::Crypto(format!("Failed decrypting JWE: {err}")))?;
    Ok(payload)
}
