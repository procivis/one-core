use std::str::FromStr;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadCore, AeadInPlace, Aes256Gcm, KeyInit};
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use ed25519_compact::x25519;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::JwkEcKey;
use p256::NistP256;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::encryption::EncryptionError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Header {
    pub key_id: String,
    // apu param
    // these are raw(!) bytes, _not_ base64
    pub agreement_partyuinfo: String,
    // apv param
    // these are raw(!) bytes, _not_ base64
    pub agreement_partyvinfo: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct JweHeader<T> {
    #[serde(rename = "kid")]
    pub key_id: String,
    // apu param
    #[serde(rename = "apu")]
    pub agreement_partyuinfo: String,
    // apv param
    #[serde(rename = "apv")]
    pub agreement_partyvinfo: String,
    #[serde(rename = "epk")]
    pub ephemeral_public_key: T,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl TryFrom<JwkEcKey> for RemoteJwk {
    type Error = EncryptionError;

    fn try_from(value: JwkEcKey) -> Result<Self, Self::Error> {
        let point = value.to_encoded_point::<NistP256>().map_err(|e| {
            EncryptionError::Crypto(format!("failed to convert JWK to encoded point: {}", e))
        })?;
        let x = Base64UrlSafeNoPadding::encode_to_string(
            point
                .x()
                .ok_or(EncryptionError::Crypto("missing x coordinate".to_string()))?,
        )
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode x coordinate: {}", e)))?;
        let y = Base64UrlSafeNoPadding::encode_to_string(
            point
                .y()
                .ok_or(EncryptionError::Crypto("missing y coordinate".to_string()))?,
        )
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode x coordinate: {}", e)))?;
        Ok(Self {
            kty: "EC".to_string(),
            crv: value.crv().to_string(),
            x,
            y: Some(y),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, ZeroizeOnDrop)]
struct PrivateJwk {
    #[zeroize(skip)]
    pub kty: String,
    #[zeroize(skip)]
    pub crv: String,
    #[zeroize(skip)]
    pub x: String,
    #[zeroize(skip)]
    pub y: Option<String>,
    pub d: String,
}

/// Construct JWE using AES256GCM encryption
pub fn build_jwe(
    payload: &[u8],
    header: Header,
    shared_secret: Zeroizing<Vec<u8>>,
    remote_jwk: RemoteJwk,
) -> Result<String, EncryptionError> {
    let apu_b64 = Base64UrlSafeNoPadding::encode_to_string(&header.agreement_partyuinfo)
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode apu: {}", e)))?;
    let apv_b64 = Base64UrlSafeNoPadding::encode_to_string(&header.agreement_partyvinfo)
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode apv: {}", e)))?;
    let protected_header = json!({
        "kid": header.key_id,
        "enc": "A256GCM",
        "alg": "ECDH-ES",
        "apu": apu_b64,
        "apv": apv_b64,
        "epk": remote_jwk,
    });
    let protected_header_bytes = serde_json::to_vec(&protected_header).map_err(|e| {
        EncryptionError::Crypto(format!("failed to serialize protected JWE header: {}", e))
    })?;
    let protected_header_b64 = Base64UrlSafeNoPadding::encode_to_string(protected_header_bytes)
        .map_err(|e| {
            EncryptionError::Crypto(format!("failed to encode protected JWE header: {}", e))
        })?;

    let encryption_key = derive_encryption_key_aes256gcm(
        &shared_secret,
        header.agreement_partyuinfo.as_bytes(),
        header.agreement_partyvinfo.as_bytes(),
    )?;

    let nonce = Aes256Gcm::generate_nonce(&mut ChaCha20Rng::from_entropy());
    let mut encrypted = payload.to_vec();
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&*encryption_key));
    let tag = cipher
        .encrypt_in_place_detached(&nonce, protected_header_b64.as_bytes(), &mut encrypted)
        .map_err(|e| EncryptionError::Crypto(format!("Failed to encrypt JWE: {}", e)))?;

    let nonce_b64 = Base64UrlSafeNoPadding::encode_to_string(nonce)
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode JWE nonce: {}", e)))?;
    let encrypted_b64 = Base64UrlSafeNoPadding::encode_to_string(encrypted)
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode JWE payload: {}", e)))?;
    let tag_b64 = Base64UrlSafeNoPadding::encode_to_string(tag)
        .map_err(|e| EncryptionError::Crypto(format!("failed to encode JWE tag: {}", e)))?;

    Ok([
        protected_header_b64,
        "".to_string(),
        nonce_b64,
        encrypted_b64,
        tag_b64,
    ]
    .join("."))
}

pub fn extract_jwe_header(jwe: &str) -> Result<Header, EncryptionError> {
    let header_b64 = jwe
        .split('.')
        .next()
        .ok_or_else(|| EncryptionError::Crypto("Invalid JWE".to_string()))?;

    let header_bytes = decode_b64(header_b64, "JWE header")?;
    let header: JweHeader<RemoteJwk> = serde_json::from_slice(&header_bytes)
        .map_err(|e| EncryptionError::Crypto(format!("Failed to parse JWE header: {}", e)))?;

    let agreement_partyuinfo =
        String::from_utf8(decode_b64(header.agreement_partyuinfo.as_str(), "apu")?).map_err(
            |e| EncryptionError::Crypto(format!("Failed to parse apu to string: {}", e)),
        )?;
    let agreement_partyvinfo =
        String::from_utf8(decode_b64(header.agreement_partyvinfo.as_str(), "apv")?).map_err(
            |e| EncryptionError::Crypto(format!("Failed to parse apv to string: {}", e)),
        )?;
    Ok(Header {
        agreement_partyuinfo,
        agreement_partyvinfo,
        key_id: header.key_id,
    })
}

pub fn decrypt_jwe_payload(
    jwe: &str,
    private_jwk: Zeroizing<String>,
) -> Result<Vec<u8>, EncryptionError> {
    let encrypted_jwe = EncryptedJWE::from_str(jwe)?;
    encrypted_jwe.decrypt(private_jwk)
}

struct EncryptedJWE {
    protected_header_b64: String,
    protected_header: Vec<u8>,
    nonce: Vec<u8>,
    payload: Vec<u8>,
    tag: Vec<u8>,
}

impl EncryptedJWE {
    fn decrypt(&self, private_key_jwk: Zeroizing<String>) -> Result<Vec<u8>, EncryptionError> {
        let private_jwk: PrivateJwk = serde_json::from_str(&private_key_jwk)
            .map_err(|e| EncryptionError::Crypto(format!("Failed to parse private JWK: {}", e)))?;

        let shared_secret = match (private_jwk.kty.as_str(), private_jwk.crv.as_str()) {
            ("EC", "P-256") => self.derive_shared_secret_p256(private_key_jwk)?,
            ("OKP", "Ed25519") | ("OKP", "X25519") => {
                self.derive_shared_secret_x25519(&private_jwk)?
            }
            (kty, crv) => {
                return Err(EncryptionError::Crypto(format!(
                    "Unsupported JWK kty \"{kty}\" and crv \"{crv}\" combination"
                )))
            }
        };

        let encryption_key = self.derive_encryption_key(&*shared_secret)?;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(&*encryption_key));
        let mut plaintext = self.payload.clone();
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&self.nonce),
                self.protected_header_b64.as_bytes(),
                &mut plaintext,
                GenericArray::from_slice(&self.tag),
            )
            .map_err(|e| EncryptionError::Crypto(format!("Failed to decrypt JWE: {}", e)))?;
        Ok(plaintext)
    }

    fn derive_shared_secret_p256(
        &self,
        jwk: Zeroizing<String>,
    ) -> Result<Zeroizing<[u8; 32]>, EncryptionError> {
        let private_key_jwk: JwkEcKey = serde_json::from_str(&jwk)
            .map_err(|e| EncryptionError::Crypto(format!("Failed to parse JWK: {}", e)))?;
        let secret_key = private_key_jwk.to_secret_key::<NistP256>().map_err(|e| {
            EncryptionError::Crypto(format!("Failed to decode JWK to secret key: {}", e))
        })?;
        let header: JweHeader<JwkEcKey> = serde_json::from_slice(&self.protected_header)
            .map_err(|e| EncryptionError::Crypto(format!("Failed to parse JWE header: {}", e)))?;
        let peer_pub_key: p256::PublicKey =
            header.ephemeral_public_key.to_public_key().map_err(|e| {
                EncryptionError::Crypto(format!("Failed to decode JWK to public key: {}", e))
            })?;

        let shared_secret: [u8; 32] =
            diffie_hellman(&secret_key.to_nonzero_scalar(), peer_pub_key.as_affine())
                .raw_secret_bytes()
                .as_slice()
                .try_into()
                .map_err(|e| {
                    EncryptionError::Crypto(format!("failed to convert to array: {}", e))
                })?;
        Ok(Zeroizing::new(shared_secret))
    }

    fn derive_shared_secret_x25519(
        &self,
        private_key_jwk: &PrivateJwk,
    ) -> Result<Zeroizing<[u8; 32]>, EncryptionError> {
        let header: JweHeader<RemoteJwk> =
            serde_json::from_slice(&self.protected_header).map_err(|e| {
                EncryptionError::Crypto(format!("Failed to decode JWK to secret key: {}", e))
            })?;
        let x = decode_b64(header.ephemeral_public_key.x.as_str(), "x coordinate")?;
        let peer_pub_key = x25519::PublicKey::from_slice(&x).map_err(|e| {
            EncryptionError::Crypto(format!("Failed to decode peer public key: {}", e))
        })?;

        let secret_key = x25519_secret_key_from_jwk(private_key_jwk)?;
        let shared_secret = peer_pub_key.dh(&secret_key).map_err(|e| {
            EncryptionError::Crypto(format!("Failed to derive shared secret: {}", e))
        })?;
        Ok(Zeroizing::new(*shared_secret))
    }

    fn derive_encryption_key(
        &self,
        shared_secret: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, EncryptionError> {
        let header: JweHeader<RemoteJwk> = serde_json::from_slice(&self.protected_header)
            .map_err(|e| EncryptionError::Crypto(format!("Failed to parse JWE header: {}", e)))?;

        let apu = decode_b64(header.agreement_partyuinfo.as_str(), "apu")?;
        let apv = decode_b64(header.agreement_partyvinfo.as_str(), "apv")?;

        derive_encryption_key_aes256gcm(shared_secret, &apu, &apv)
    }
}

fn derive_encryption_key_aes256gcm(
    shared_secret: &[u8],
    apu: &[u8],
    apv: &[u8],
) -> Result<Zeroizing<[u8; 32]>, EncryptionError> {
    const ALG: &[u8] = b"A256GCM";
    const KEY_LENGTH: u32 = 256;

    let mut other_info = vec![];
    other_info.extend((ALG.len() as u32).to_be_bytes());
    other_info.extend(ALG);
    other_info.extend((apu.len() as u32).to_be_bytes());
    other_info.extend(apu);
    other_info.extend((apv.len() as u32).to_be_bytes());
    other_info.extend(apv);
    other_info.extend(KEY_LENGTH.to_be_bytes());

    let mut encryption_key = Zeroizing::new([0; 32]);
    concat_kdf::derive_key_into::<sha2::Sha256>(shared_secret, &other_info, &mut *encryption_key)
        .map_err(|e| EncryptionError::Crypto(format!("Failed to derive encryption key: {}", e)))?;
    Ok(encryption_key)
}

fn x25519_secret_key_from_jwk(jwk: &PrivateJwk) -> Result<x25519::SecretKey, EncryptionError> {
    let d = decode_b64(jwk.d.as_str(), "private key value d")?;

    match jwk.crv.as_str() {
        "Ed25519" => {
            let ed25519_key = ed25519_compact::SecretKey::from_slice(&d).map_err(|e| {
                EncryptionError::Crypto(format!("Failed to create ed25519 key: {}", e))
            })?;
            x25519::SecretKey::from_ed25519(&ed25519_key).map_err(|e| {
                EncryptionError::Crypto(format!(
                    "Failed to convert ed25519 key to x25519 key: {}",
                    e
                ))
            })
        }
        "X25519" => x25519::SecretKey::from_slice(&d)
            .map_err(|e| EncryptionError::Crypto(format!("Failed to create x25519 key: {}", e))),
        crv => Err(EncryptionError::Crypto(format!(
            "unsupported crv \"{crv}\""
        ))),
    }
}

impl FromStr for EncryptedJWE {
    type Err = EncryptionError;

    fn from_str(jwe: &str) -> Result<Self, Self::Err> {
        let parts = jwe.split('.').collect::<Vec<_>>();
        if parts.len() != 5 {
            return Err(EncryptionError::Crypto(format!(
                "Invalid JWE: expected 5 parts but found {}",
                parts.len()
            )));
        }
        if !parts[1].is_empty() {
            return Err(EncryptionError::Crypto(
                "Invalid JWE: expected empty CEK".to_string(),
            ));
        }
        let protected_header = decode_b64(parts[0], "protected header")?;
        let nonce = decode_b64(parts[2], "nonce")?;
        let payload = decode_b64(parts[3], "payload")?;
        let tag = decode_b64(parts[4], "tag")?;
        Ok(Self {
            protected_header_b64: parts[0].to_string(),
            protected_header,
            nonce,
            payload,
            tag,
        })
    }
}

pub(crate) fn decode_b64(base64_input: &str, name: &str) -> Result<Vec<u8>, EncryptionError> {
    Base64UrlSafeNoPadding::decode_to_vec(base64_input, None)
        .map_err(|e| EncryptionError::Crypto(format!("Failed to decode {}: {}", name, e)))
}

#[cfg(test)]
mod test {
    use super::*;

    const PRIVATE_JWK_EC: &str = r#"{"kty":"EC","crv":"P-256","x":"KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo","y":"d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU","d":"81vofgUlDnb6OUF-WPhH8p1T_mo_F2H9XZvaTvtEZHk"}"#;
    const PRIVATE_JWK_ED25519: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM","d":"IM92LwWowNDr7OHXEYwuZ1uVm71ihELJda3i50doJ53TISuUpwwLHkMbrOaChSecW8sERC65hZBJggvBXY71Mw"}"#;

    #[test]
    fn test_decrypt_jwe_ec() {
        let expected_payload = "eyJhdWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9vaWRjLXZlcmlmaWVyL3YxL3Jlc3BvbnNlIiwiZXhwIjoxNzMxNTA5NDY5LCJ2cF90b2tlbiI6Im8yZDJaWEp6YVc5dVl6RXVNR2xrYjJOMWJXVnVkSE9CbzJka2IyTlVlWEJsZFc5eVp5NXBjMjh1TVRnd01UTXVOUzR4TG0xRVRHeHBjM04xWlhKVGFXZHVaV1NpYW01aGJXVlRjR0ZqWlhPaFpIUmxjM1NCMkJoWVg2Um9aR2xuWlhOMFNVUUFabkpoYm1SdmJWZ2dBQnBqa1h3Q2RYdVJUdUlaU3RqWnRCZ0dhZ3FqcFlpeGMxSWFINUpRY1JweFpXeGxiV1Z1ZEVsa1pXNTBhV1pwWlhKbWRtRnNkV1V4YkdWc1pXMWxiblJXWVd4MVpXUjBaWE4wYW1semMzVmxja0YxZEdpRVE2RUJKcUVZSVZrRGx6Q0NBNU13Z2dNNG9BTUNBUUlDRkVQamdGUExNb1NmRk4xSVRPeDc0OUlKWWFtQ01Bb0dDQ3FHU000OUJBTUNNR0l4Q3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRSERBWmFkWEpwWTJneEVUQVBCZ05WQkFvTUNGQnliMk5wZG1sek1SRXdEd1lEVlFRTERBaFFjbTlqYVhacGN6RWNNQm9HQTFVRUF3d1RZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFlRncweU5ERXhNVE14TkRBMU1EQmFGdzB5TlRBeU1URXdNREF3TURCYU1Fb3hDekFKQmdOVkJBWVRBa05JTVE4d0RRWURWUVFIREFaYWRYSnBZMmd4RkRBU0JnTlZCQW9NQzFCeWIyTnBkbWx6SUVGSE1SUXdFZ1lEVlFRRERBdHdjbTlqYVhacGN5NWphREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQ2tTU0YxUHFjaEhCMUVVVVVPZUkwNGZUMDA1Z1dLSU9lNjBBOWJnckw4S2QzMURaY1JTcWF4QVVHQnQ3MEhCN3VDWmR1ZkE2dUtkTDZCdkF6VWhiSldqZ2dIaU1JSUIzakFPQmdOVkhROEJBZjhFQkFNQ0I0QXdGUVlEVlIwbEFRSF9CQXN3Q1FZSEtJR01YUVVCQWpBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRk8wYXNKM2lZRVZRQUR2YVdqUXlHcGktTGJmRk1Gb0dBMVVkSHdSVE1GRXdUNkJOb0V1R1NXaDBkSEJ6T2k4dlkyRXVaR1YyTG0xa2JDMXdiSFZ6TG1OdmJTOWpjbXd2TkRCRFJESXlOVFEzUmpNNE16UkROVEkyUXpWRE1qSkZNVUV5TmtNM1JUSXdNek15TkRZMk9DOHdnY29HQ0NzR0FRVUZCd0VCQklHOU1JRzZNRnNHQ0NzR0FRVUZCekFDaGs5b2RIUndjem92TDJOaExtUmxkaTV0Wkd3dGNHeDFjeTVqYjIwdmFYTnpkV1Z5THpRd1EwUXlNalUwTjBZek9ETTBRelV5TmtNMVF6SXlSVEZCTWpaRE4wVXlNRE16TWpRMk5qZ3VaR1Z5TUZzR0NDc0dBUVVGQnpBQmhrOW9kSFJ3Y3pvdkwyTmhMbVJsZGk1dFpHd3RjR3gxY3k1amIyMHZiMk56Y0M4ME1FTkVNakkxTkRkR016Z3pORU0xTWpaRE5VTXlNa1V4UVRJMlF6ZEZNakF6TXpJME5qWTRMMk5sY25Rdk1DWUdBMVVkRWdRZk1CMkdHMmgwZEhCek9pOHZZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFXQmdOVkhSRUVEekFOZ2d0d2NtOWphWFpwY3k1amFEQWRCZ05WSFE0RUZnUVVoSVZ4XzRLOHVEU2dUTG4yZnhaT2VaaWxhSkV3Q2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQUlNUlllcmhWNWYtdGRwbVpuZjRYRXRLVmQyMUQzVlpwcGNNbHNpcHBYNXdBaUVBMnJJV3FnQWpla1JMcWYxaGM5bjlSSFV3eklnVnF1OVplc2FCSDZkcWhieFpBVkhZR0ZrQlRLWm5kbVZ5YzJsdmJtTXhMakJ2WkdsblpYTjBRV3huYjNKcGRHaHRaMU5JUVMweU5UWnNkbUZzZFdWRWFXZGxjM1J6b1dSMFpYTjBvUUJZSUNPSVpMdlZTaUJCWnNVTHo0VTluQnZDZUxnV0FScVFZeE9RWTdCQkxIQWxiV1JsZG1salpVdGxlVWx1Wm0taGFXUmxkbWxqWlV0bGVhTUJBU0FHSVZnZ0dFMXZRVS13MDZmc1o4WVZpS3hrTnc3MXduY1BaUmpDdW9oTXJIVDBvdEpuWkc5alZIbHdaWFZ2Y21jdWFYTnZMakU0TURFekxqVXVNUzV0UkV4c2RtRnNhV1JwZEhsSmJtWnZwR1p6YVdkdVpXVEFkREl3TWpRdE1URXRNVE5VTVRRNk1qVTZNVEZhYVhaaGJHbGtSbkp2YmNCME1qQXlOQzB4TVMweE0xUXhORG95TlRveE1WcHFkbUZzYVdSVmJuUnBiTUIwTWpBeU5DMHhNUzB4TmxReE5Eb3lOVG94TVZwdVpYaHdaV04wWldSVmNHUmhkR1hBZERJd01qUXRNVEV0TVRSVU1UUTZNalU2TVRGYVdFQnpBc0tGNGVKZzdFNFJTdUx4RjJDQk5YZzdpWUREMklsN3dTN1dkLXJVa2VQbWRjS1Jld0VQX3ZVSjlmbVRlLV9SYmZUM0dkeTV1Yndtbl9qTDY4TmxiR1JsZG1salpWTnBaMjVsWktKcWJtRnRaVk53WVdObGM5Z1lRYUJxWkdWMmFXTmxRWFYwYUtGdlpHVjJhV05sVTJsbmJtRjBkWEpsaEVPaEFTZWc5bGhBV2Z6c00tOEI0SF9xLTRXdVJnZVlQbjNhNEMydUxjQkdKam1qV3FJSTFGeS1tb0JOcV9FU3FkTkcycFZGYlZoVkh1Nm9pTUxLU0FFRHh2WHNjRlJUQkdaemRHRjBkWE1BIiwicHJlc2VudGF0aW9uX3N1Ym1pc3Npb24iOnsiaWQiOiJiOTE0NWEyYS00MDY0LTRhZjMtODY5Yi0xYzhkMmZkOGUzYzciLCJkZWZpbml0aW9uX2lkIjoiYzQ2MzU1NTMtMjQ5Ni00ZGIwLTg5OWUtNTFkZDkyNDJiZjZiIiwiZGVzY3JpcHRvcl9tYXAiOlt7ImlkIjoiaW5wdXRfMCIsImZvcm1hdCI6Im1zb19tZG9jIiwicGF0aCI6IiQiLCJwYXRoX25lc3RlZCI6eyJmb3JtYXQiOiJtc29fbWRvYyIsInBhdGgiOiIkLnZwLnZlcmlmaWFibGVDcmVkZW50aWFsWzBdIn19XX0sInN0YXRlIjoiYzQ2MzU1NTMtMjQ5Ni00ZGIwLTg5OWUtNTFkZDkyNDJiZjZiIn0";
        let expected_header = Header {
            key_id: "eec37767-ad74-47c9-a349-d95a1bd241d4".to_string(),
            agreement_partyuinfo:
                "\u{18}G\u{7}Ëcr\u{5}Þ§ù\u{97}~Ê0W>9FÖ=\u{17}¹v\u{7f}®ô\u{c}h\u{1c}u\u{99}Ç"
                    .to_string(),
            agreement_partyvinfo: "bueFnxmWT1EJEmPB5zq4m6aqkhEjIN8j".to_string(),
        };
        let jwe = "eyJraWQiOiJlZWMzNzc2Ny1hZDc0LTQ3YzktYTM0OS1kOTVhMWJkMjQxZDQiLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjoiR0VjSHc0dGpjZ1hEbnNLbnc3bkNsMzdEaWpCWFBqbEd3NVk5RjhLNWRuX0Nyc08wREdnY2RjS1p3NGMiLCJhcHYiOiJZblZsUm01NGJWZFVNVVZLUlcxUVFqVjZjVFJ0Tm1GeGEyaEZha2xPT0dvIiwiZXBrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiM0JNNlpmcGU0S1FnUmJWMWVQbFc4M0dNX0xXU3VIWGpTWWwwTEVXeEdFSSIsInkiOiJmWmFlQW95MGd2M2xNd3VWaWpFSGNJejJvMk9xcE0yWXB3MFBrenFTREhZIn0sImFsZyI6IkVDREgtRVMifQ..FanNHP6n423XnuTq.olGWlNYGVyKkQsXcokpxvD_3iy_eVKXOPmmbveZkqYzHMi-OnNJXQ5ppbrzL43Mj9AqJFmMuKaQ1tHrsTfK_nPr_cuGn2qd4Xo-Y027Ij0jff5cFCf_9AtLLz8zlIYsKJTm97otqH3dXwfDNA7QZAIV6zOMPHzOGQj1186edqPukjkslFhVvxnqvc5Ukq2qheAYlc9sK2k38dAWSpVARFZxGjE8c7V_lXS6RqDQjX48677je0LXyfi6VrJ1M78fTfWhP3mjtuLWUGM9_94E1xlb6RZaW8Iz16Efbl6RxBpC-9ogDG9id8IAfzeKlGEVTepfnRlNovTb0j8kAyhfQ5KZQRN9x6_ltzoGb8MNknx6CeU29aqpiek1kADqFn0O6LMhKDEVNncNth2loPh8Fvjd3TOJwx9b1j2KsfgW3hwST8O4el529rkidW1GKZ4sF5bGV07QiDFC_BPDgmpon9diwL9t-z6EXzvksi9WVyQqCOvjNp-EoQvgcfkwvl-lgCOFR7cAKbX6L-NlP6wz20btIILE0238lnYTFL4oPVDJnt9RspFVrMs-8hifUsAAzqxt2oy6JIqRKmZjqJyBN2JauREV4L3fbkJrgqo6qtneEVeRXk9TGhoSS-ZVajIFlIpw7d-ufs-odR8cIuRX2mWKoAX6cC7WCCKALIzT_CbvWXmTkGmZk7CRCoRQgIPveazy5JY-M8-501rabzF-980IHyDYn3OvzBXzY2MUgfWvhVhdZHJR8fmAWYJehf8v3uTUeJHtuPQAQYCt0Wwgqz71dusfCBjPmVpsu9G8Gkd6kWMiQDIVH0iF9sGJlDZCu2SouPF8pixB3PvpeM_sXBaFqqT9vZEEV0c5yppgpvTsd-rWNWiz1AZ5rFDsh0h1qx68OcGg6ZV3LBX4hNp0yQn2ekh6v_1pnJJufyME9_hwRezlE-do_E2Xi-SjEFpBnk5od_MtCdAzAAUKJMDPuBIzN9Xdu2F9EAiyzP7FwiCGYcrnO8c9TGdFCjOMUhrxOvJ62Kdp7UAQEdRKCGD3KW9py5gF5WLs_WOiNDta5CImHwomscLo9TBntSYqXvDnm-xlCXNkYvL7E2ZBVFkSrGgqjoKqwYP4Uo6TfIPWtr-NHFnISzUuYweM-NUV_XT35DgZME98f-vzPo47sX6fOH6CaTEcGv1alLOsE9XVPs-U87GreE70JtDsAKgCyCGk7oI_3EhdOjrBEzUYuwYdZj4EJ1jhhNYuvJMZWg0KxOof90MUAXZZpN3RA_1by99Z0r_PW34VJkE6Y-TdA70qjhWoZcLOOZlX2iUqIEVsHb3m8mTSlF3llc5DpQnB9GKINWpuxR7s7XgJkDgb_Vjze5OFn1YTfJvhicc5yjsWZ072Rd0i9OPdJqpMmB9tgiN57PyhrLLD3Rx88QbXf9n50lYnkTLJtFZ0sDx-U58L6HdqE2Xio4mjdoVy_1_H2nDIP0W_17k-qYQwUJIcP1V7sZNr0l8S3IQqZhARw3VmlM7WrkeWD0laonIQok7T4Ue39-3D3NmP6VPFvJx_hk-lYiXNrcmlAo-RgvJLdzyFw3ekbSqyfzFt33PBm0htwErkO5nN68eyAYIZ6A6LyToZwA0JhZh6MqftqlGHsRG3XtrEfvrd94DymLjLp6rmKpMgHBQSzwYSp15VN16oSP40eUWWVXbsrEhxjXD-iCn-Zz5K35A3NDQsIS5712FD5lRbqf0LWVSsdNYy0gr5A7bC3ePbkmBzOWPcDiLDq8sO4fleavT4jNjGviSfGwFFONwpKEgVKM8KOb5f8Ric9V-GmqmXIDsv3NYDYAR1GJHkrJ-lN4txLLruosKT490NV7EdaNxqQKSbBlGoh6UNT71SdN2IqqIfup5fDndReMl05Mlb9feUkqC6UWl6H3LShHiuZKXwIY-ZNtSAmokBze3LRkyHB66pZgE7krAUEyVX7DnpxaBgCrrA7tK2Kuo3aYcjXjOIpHHplORwPoUsHB_bBeinsYX6U5PKvvOIsokJOppNbwyeqABEhao7uiBeSiqzNa0iHPrTqTcTDxkl4HcQgq_y_P8LAZTZjW9713W5ujS-OyRef3VO15rm9QH6wkP4WR532Ep126soW429q9e0b5Q3ECB7Wg8FsX2IJoAsrPELPaJ_cHbzRNiecxF-lbG8Tf6mkagY5dQq9tEocdT52FVimhHg4DOfVyhWNw9VzVtGkyXxARjw4o89qR0kS0dnTIwD7609Kftmux44xhNXeWNMTlPzleOZGa1-65zEth2X9BhVFWzD92dMBLJRWPRRq7eBLG2X3oQMLRmMigkxq0KenZUK7GBDaRLj-JXSXyOhs0ZyA2AN5Y7Kntdq7fC_ZiWS-WiU495f9y0WqveRJF-NwWulOJ5LMdIwvNDinrbHUSKZZIdqI32JtAMgcrj4KiK3yjHfufL0N7zwwu6U6ezqJikSn0q5ptxcJVmNoi6nkycYOnW17c029IOiTQokQWDOdgxo4PjcZUD-XvCib2a-znLIEfio3LyWC9ZAgm02_3PttaHxR4jRdtKXy4EEZ-kNqBstVJqm0eW1o3abjUmm3ZYwtFdbFuRbI_y3mIwrVlkq8eeuosab76gCB171-VYYNAqnt_ERvsBHeLzv0-8DrKh5n6mmjVn-hbr8NgLyUhCuwZqDJvc3Cru-UwZLxwjrYIpRHoCK5K_92u8-QcSdZ-9Oz6PCBNUAssjzEyCrmcPnI6J0tj_Iacrj91m_Ytp17aIS16kCqwKQgfpa1E4tYbepPvO9TwQNq-zrgQhMvy2muZxrfYRvFqo6GVvBmLf4A1811szaTv3KPv86TdM_0E-cjCbwoBUWAVgy_cb5-7r5rRTObbVhA8oxrq8F_LSVMJLh9DyszpNHMpJiisdmzELWjqIUOFqP1nJBOojbI7Db-YlN_utfBVW0fZB5iB6rzioQopkHViKbZYW1wfPLyHcLW1Ddqdj2WWDnR770CpLxMgCzfrOshF4Kosz1rgCCv-PjpXuq7ht5_5hdK6kHcIyj-gr1xPAoojPbscjPrcJJQNyy79qoQfTHqI8zDoCqNTtJn-7UGCmDd8y7x_NeUf4EijrKujuHoXz3P_6ZHSP7syHUIoGsyVj9YK8U5oQKEssCHNL6YmR9iPwefLSfEIqnUghUaIUnULrU7sHDq0oF64ImvQEMK_jRY5L-Aa1Uu7wsotYoW2K-JUw8lKPBQuykfR3CJnwb9wN7IHKUV8AWwIwK_PUry7fhoRjQESbgj1xqZVpy1oJEmo9N-dm470oOyTwhU7NqknObJB88QhiumBBcTIlm6FkPunw1vIBNlBSVD_p9zoUJiBhLljnTfbYOFKxNTj2EgJsYIhQqepA923DPQqsm_vHlIwQeIRHV6WHpDULsiWeHHrDIf57pUy73oN38rEQQiCB86lHXGscnyJum3itzSF8dMf852lGZyaMSXqX2sUCY-dsf-wsfQlfkSVK3Hi1hxmFgCTarRY_qnZLCQktM.DshBdcfiHuDRQlCAJMDNBQ";

        let extracted_header = extract_jwe_header(jwe).unwrap();
        assert_eq!(expected_header, extracted_header);

        let decrypted_payload_bytes =
            decrypt_jwe_payload(jwe, PRIVATE_JWK_EC.to_string().into()).unwrap();
        assert_eq!(
            Base64UrlSafeNoPadding::encode_to_string(decrypted_payload_bytes).unwrap(),
            expected_payload
        )
    }

    #[test]
    fn test_decrypt_jwe_eddsa() {
        let expected_payload = "eyJhdWQiOiJodHRwOi8vMC4wLjAuMDozMDAwL3NzaS9vaWRjLXZlcmlmaWVyL3YxL3Jlc3BvbnNlIiwiZXhwIjoxNzMxNTEwNzg5LCJ2cF90b2tlbiI6Im8yZDJaWEp6YVc5dVl6RXVNR2xrYjJOMWJXVnVkSE9CbzJka2IyTlVlWEJsZFc5eVp5NXBjMjh1TVRnd01UTXVOUzR4TG0xRVRHeHBjM04xWlhKVGFXZHVaV1NpYW01aGJXVlRjR0ZqWlhPaFpIUmxjM1NCMkJoWVg2Um9aR2xuWlhOMFNVUUFabkpoYm1SdmJWZ2dBQnBqa1h3Q2RYdVJUdUlaU3RqWnRCZ0dhZ3FqcFlpeGMxSWFINUpRY1JweFpXeGxiV1Z1ZEVsa1pXNTBhV1pwWlhKbWRtRnNkV1V4YkdWc1pXMWxiblJXWVd4MVpXUjBaWE4wYW1semMzVmxja0YxZEdpRVE2RUJKcUVZSVZrRGx6Q0NBNU13Z2dNNG9BTUNBUUlDRkVQamdGUExNb1NmRk4xSVRPeDc0OUlKWWFtQ01Bb0dDQ3FHU000OUJBTUNNR0l4Q3pBSkJnTlZCQVlUQWtOSU1ROHdEUVlEVlFRSERBWmFkWEpwWTJneEVUQVBCZ05WQkFvTUNGQnliMk5wZG1sek1SRXdEd1lEVlFRTERBaFFjbTlqYVhacGN6RWNNQm9HQTFVRUF3d1RZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFlRncweU5ERXhNVE14TkRBMU1EQmFGdzB5TlRBeU1URXdNREF3TURCYU1Fb3hDekFKQmdOVkJBWVRBa05JTVE4d0RRWURWUVFIREFaYWRYSnBZMmd4RkRBU0JnTlZCQW9NQzFCeWIyTnBkbWx6SUVGSE1SUXdFZ1lEVlFRRERBdHdjbTlqYVhacGN5NWphREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQ2tTU0YxUHFjaEhCMUVVVVVPZUkwNGZUMDA1Z1dLSU9lNjBBOWJnckw4S2QzMURaY1JTcWF4QVVHQnQ3MEhCN3VDWmR1ZkE2dUtkTDZCdkF6VWhiSldqZ2dIaU1JSUIzakFPQmdOVkhROEJBZjhFQkFNQ0I0QXdGUVlEVlIwbEFRSF9CQXN3Q1FZSEtJR01YUVVCQWpBTUJnTlZIUk1CQWY4RUFqQUFNQjhHQTFVZEl3UVlNQmFBRk8wYXNKM2lZRVZRQUR2YVdqUXlHcGktTGJmRk1Gb0dBMVVkSHdSVE1GRXdUNkJOb0V1R1NXaDBkSEJ6T2k4dlkyRXVaR1YyTG0xa2JDMXdiSFZ6TG1OdmJTOWpjbXd2TkRCRFJESXlOVFEzUmpNNE16UkROVEkyUXpWRE1qSkZNVUV5TmtNM1JUSXdNek15TkRZMk9DOHdnY29HQ0NzR0FRVUZCd0VCQklHOU1JRzZNRnNHQ0NzR0FRVUZCekFDaGs5b2RIUndjem92TDJOaExtUmxkaTV0Wkd3dGNHeDFjeTVqYjIwdmFYTnpkV1Z5THpRd1EwUXlNalUwTjBZek9ETTBRelV5TmtNMVF6SXlSVEZCTWpaRE4wVXlNRE16TWpRMk5qZ3VaR1Z5TUZzR0NDc0dBUVVGQnpBQmhrOW9kSFJ3Y3pvdkwyTmhMbVJsZGk1dFpHd3RjR3gxY3k1amIyMHZiMk56Y0M4ME1FTkVNakkxTkRkR016Z3pORU0xTWpaRE5VTXlNa1V4UVRJMlF6ZEZNakF6TXpJME5qWTRMMk5sY25Rdk1DWUdBMVVkRWdRZk1CMkdHMmgwZEhCek9pOHZZMkV1WkdWMkxtMWtiQzF3YkhWekxtTnZiVEFXQmdOVkhSRUVEekFOZ2d0d2NtOWphWFpwY3k1amFEQWRCZ05WSFE0RUZnUVVoSVZ4XzRLOHVEU2dUTG4yZnhaT2VaaWxhSkV3Q2dZSUtvWkl6ajBFQXdJRFNRQXdSZ0loQUlNUlllcmhWNWYtdGRwbVpuZjRYRXRLVmQyMUQzVlpwcGNNbHNpcHBYNXdBaUVBMnJJV3FnQWpla1JMcWYxaGM5bjlSSFV3eklnVnF1OVplc2FCSDZkcWhieFpBVkhZR0ZrQlRLWm5kbVZ5YzJsdmJtTXhMakJ2WkdsblpYTjBRV3huYjNKcGRHaHRaMU5JUVMweU5UWnNkbUZzZFdWRWFXZGxjM1J6b1dSMFpYTjBvUUJZSUNPSVpMdlZTaUJCWnNVTHo0VTluQnZDZUxnV0FScVFZeE9RWTdCQkxIQWxiV1JsZG1salpVdGxlVWx1Wm0taGFXUmxkbWxqWlV0bGVhTUJBU0FHSVZnZ0dFMXZRVS13MDZmc1o4WVZpS3hrTnc3MXduY1BaUmpDdW9oTXJIVDBvdEpuWkc5alZIbHdaWFZ2Y21jdWFYTnZMakU0TURFekxqVXVNUzV0UkV4c2RtRnNhV1JwZEhsSmJtWnZwR1p6YVdkdVpXVEFkREl3TWpRdE1URXRNVE5VTVRRNk1qVTZNVEZhYVhaaGJHbGtSbkp2YmNCME1qQXlOQzB4TVMweE0xUXhORG95TlRveE1WcHFkbUZzYVdSVmJuUnBiTUIwTWpBeU5DMHhNUzB4TmxReE5Eb3lOVG94TVZwdVpYaHdaV04wWldSVmNHUmhkR1hBZERJd01qUXRNVEV0TVRSVU1UUTZNalU2TVRGYVdFQnpBc0tGNGVKZzdFNFJTdUx4RjJDQk5YZzdpWUREMklsN3dTN1dkLXJVa2VQbWRjS1Jld0VQX3ZVSjlmbVRlLV9SYmZUM0dkeTV1Yndtbl9qTDY4TmxiR1JsZG1salpWTnBaMjVsWktKcWJtRnRaVk53WVdObGM5Z1lRYUJxWkdWMmFXTmxRWFYwYUtGdlpHVjJhV05sVTJsbmJtRjBkWEpsaEVPaEFTZWc5bGhBdkd2MUUwanZOR05ZY21wbllqMWRKRUJ5MFZ2alJZWkNXWm1pdWRpRC1ETEdyQi1lc1JNUjhIRG9hWGx6R0xEcW5hbEVRQVQyNV82MzN5blpMcUVmQ21aemRHRjBkWE1BIiwicHJlc2VudGF0aW9uX3N1Ym1pc3Npb24iOnsiaWQiOiJkYmEwZTQ5MS1iNjk5LTRkM2UtYTQ0YS01MTg4OWE2MmQzNmIiLCJkZWZpbml0aW9uX2lkIjoiZGFkZTE1MmItYjg1NS00NWNiLWJkZjAtNTIyZmUxNWMwOWI3IiwiZGVzY3JpcHRvcl9tYXAiOlt7ImlkIjoiaW5wdXRfMCIsImZvcm1hdCI6Im1zb19tZG9jIiwicGF0aCI6IiQiLCJwYXRoX25lc3RlZCI6eyJmb3JtYXQiOiJtc29fbWRvYyIsInBhdGgiOiIkLnZwLnZlcmlmaWFibGVDcmVkZW50aWFsWzBdIn19XX0sInN0YXRlIjoiZGFkZTE1MmItYjg1NS00NWNiLWJkZjAtNTIyZmUxNWMwOWI3In0";
        let expected_header = Header {
            key_id: "9be052ed-83b8-4c60-ab4f-214fe21caa93".to_string(),
            agreement_partyuinfo: "BJ\"ûzw\u{11}\u{93}\u{7}Ç>»Ý%\nÁk&âÌÕ°\u{6}\u{9e}Õ_\u{8a}Ö%#Za"
                .to_string(),
            agreement_partyvinfo: "e4xmMaGk6O2UX25eq7Opc46LU7PdzUXp".to_string(),
        };
        let jwe = "eyJraWQiOiI5YmUwNTJlZC04M2I4LTRjNjAtYWI0Zi0yMTRmZTIxY2FhOTMiLCJlbmMiOiJBMjU2R0NNIiwiYXB1IjoiUWtvaXc3dDZkeEhDa3dmRGh6N0N1OE9kSlFyRGdXc213NkxEak1PVndyQUd3cDdEbFZfQ2lzT1dKU05hWVEiLCJhcHYiOiJaVFI0YlUxaFIyczJUekpWV0RJMVpYRTNUM0JqTkRaTVZUZFFaSHBWV0hBIiwiZXBrIjp7Imt0eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJteHBhUW5zWjZFYWFUR3Y5aU1NZmQ3dGJrSUNDR1FqLUVQVGRxeDlnLTBRIn0sImFsZyI6IkVDREgtRVMifQ..yaYKT82f_9fNheZO.N3vMRP6gEbieETK9FcFdd4vF6G7rOmE_8HTGlSOncrEUsBTi6bl5mM80FSiLYwhj-EhwfKvl9AkBukWTtndMVku3dDMnK2Wn4cvjZzQE0Vqu2JyYHFsUQ9H8i-sxetfGepvIbmokN3Ihdv0w_ffTrRrpfosYunkRBBdpElTl5T2B9Goo-r4W9wWLD_2gQnVTIc8Ps2HeJbGt8kYCJyKeuyzGs9JSaHkx_pEaRU40oZKnAnwg0E6Yl394tj-tZ427_iNFhP02K5_EXFHGOLfmEVSrs3eodNzzkXH8VXqzm2ytC_g8BoIlsW6A7sudKfzYptob_lerxCxozvW06bLD-9v4PaNcA4YrShOoJsIlSIJ7ttWPInEXCl44XJS3ASKzg00oI5StDAS_AkE9rgnOkirZTRXma2NIhcNliYOzZbhcWaRYLPHunRi99Eon3rrjp3BDa6pZjMW9_dF8UzQFdQCJEWNEVuczzxCm8KYFvroh3t3RHjhvi6HV3pjz6tEx3AWoie24zLaogArtoLenqmAFF-HW_rXistJ7Rl16oksF3Yj6OhsYPkIK4tx2WnC7TNjU4GbJbIU7Z9nIjkGpgITOizW4Ps9-UZBV4gYmj8tgT1RCWbHWoC7nk2V0Mf2spKAToAzZseMYXCl35DBu0mX0h_b-AGAjVL1xhL6rtg6srlGU9cM5X4olqiHzp05vmgVJbNyQhc2wpbknMEyz0v4OTRWL5s_-Yst7rmvKtzl9JmhecE7wwmaYaqRbz5qBosPJ4zdo1RMDfnQyVIRXiMODpQUvzjANwH9YdvYU2KHFiaprbqonwrYZmoHzEqHNFZ8htzcYIZWv-4611gV4x9E_ZjtPyYQCw7RkLbokKgcwRGGRadAkznSnMWAgWJDOgx20wzsMo2WwljSScUUX-nE6itftNxcrfdR0ItwGy6558iQ_9_QJ0tkABKtu3Eb9SMkLcl5NjRn3QSJsHHumst-OD3RmCoJ_FdQzKTDAftGDeVhwhFwGdFYNWvJ-wsSUqHLnqaNIruJKPPxMrAh74nmcrn7506gtFTDzd0a4_mWjKaqHYpbZa7XLmiOPj9jd4jFTuCcSwMFu__NKsQIDMXrTQ9ddY3G6qLi8oWKP8RrgGZUvcpUYT1X1k7JO9POOghWhyvUQQJIUFWEiWxew86Owp_w9Gu4_mRg15FT8h2OEKqpHuEN7lZiaBsN5Q6dLITA4Sv98SUPZ9lD4pFW2kQLz-jgSyK7umzj-HCYb5tdrRZIcfNB91537KE7hGhA7UfzkZIw1kPuewn9KtVittXYH_CjLUTA4F0LbYZq9CwORKNsT36A06TLB2xB_VyRGNHNz5BvjfrFZJ4wyU76uS-a7_tf_y2VoaXEmRPYoBCBjpa4aW7yeDIVWIqe2vuqRN0kmY0FeYJ33jzSTVksiK1--zKvJhghek5eBmZh7Qi8PYUZvooTr19fGnveMbV7eoXGIk-_OO_vrMLchd1G3CgILlpUMjFRuSoBQWblebo3RaOTcH-rI1FXOm2L1IDezcL3oLhoGF9HGiIaq48DSI7lcG5Tkq1G2uzPWtkCG20aRFInxEMTIfTvEV0IG_oQl_F162ETkRhXQu0UdGD1gpBJiGoOCPY57g6xfINEutxesvG1Cfx8Nc0nW4wxHEU8RZRgdU2S7h8xpyDLKVLXB6Kikj8wZ9c5kGEipzNbip22rXZlJXthdKd_re70sKPAG6k_YpH4YGSSwcYSfnEHeJrlZx7-LfnLm0iTkRFuakLxCqmz3Hz1VddSQE37SDTW9wqNaa4wNq5zrvIBqSR14xgba5NZJDqKJC_493B6FQGyAY8L_4LceL4WWJw32otCojSWdChFMTiON2UHYeNKafbe_0Pgx4KrBNNeIMM4-XKFTWGPCmJWrAWHU3aROJNGSHG3dCuC1tBLSWfULJg2zd0JXday3VPA0V-scSe7DV6YTUCNjgVJp-VJymajbE54lcYz_REjCgyl9vI1LQ8uLsEHm4NKPq-93l4OBj2p1OARlLPvnn0kv_64eDa6p14FFImPnV25UqYWrzJh_0b3XLl9L-rPHLpjxun1k1i7zzDr0fuGQ3QzJXgb8Qf_krJ4J8Wz-Ftz5pU80KP0gcwlYMLf1EPsmC91N3KBXKJUMvTQirbmQPbMR85cInlshR4ksYZ55uaoqP7-byJxuCte56_B0othvxcsqsh50bMGE7T9XPCTL1UWZLnKtd6UXTk-mkyafrTOJXocjemtOAb8-P07G6ep0llejBlIQ5c9iByOfL-3DBMi3EKF0NWyixHydMzXH9Dlt2ZMqeZHcpk8paCtOGDQFdmSsbarm1eQCscqSt8VcG2rAhzSKfgFr0eT8r1EZBoIyG7oMJsfnFmAw2KsYSuAzG3z3bvwGJio9zuIP2lHHDBIA2ooAOK9V4Ppb2WjLkXuZXfGuZenEYEgM6NLxbzdGCwbnqV3IDvoQ0120gAt9dR8zVMUzFRqE6i2cvMTHn25thGKUVPAjB5goexd_9986IDDndtLk1badlAjG7_ZjBIxtqgUyNyFkM4YLDT0KVk6cCbk6VPozpgvx_k1YSKzW-8YpoO5A6rETIOGBrVG3GNdVBEZJN41JqHTNM-oi9UX7Pk6lg0ZwLKmsvaXiYLVKzP2OGezuHlipv_seBgb-HJh1d8AJUCdgj-WQ1BVusuMDUnSsQTnOyvp7Ziu6QB2xGDNEq9rdwtwagNj3EHls7RkqWane5GgHX8r4qDrQsuM2rnqydllM6Ge-pK--XupLBzjSmVXhp-MMDSovDuYOThcUeydKnpEbGCq7XRJyYbvYDbQ20d4WAysBcxR3B04oUxLWxfmrRcwUdVGT6wMEBGTtUYFfvi9GyASZkEq9FmwiG1omijIn-sxwKkCzO9V5RcnfeHFGNLGizqq-GGjdbWck3W9sly8YpmDvdFH1pUcpHyGC45d5r8d9lpg_qwuqy3XEE3qPs094qOGsGbVAf1AzMIR0P7lY-CRmUXjcxyOzpHA7r2vSJk15zxp9ffYc6CR-Sf2qhnEAEFridprCZQa7cfPVAEeppbmiRKqTex177f2qQWA08YIS0E5GSDg-FEs7jnXlCutrxzTFVetBu7Ocz_7ul6b3ouks5qPy-NYl08IOfKEmAIW1NDWNBBZcaQf6zt5SQOEpfdrvkx0Nu9n1i0Dd90SXXmKOsle2NBr-zQB5Ak4ai1-31KBpNBj2gU7TD1elGrKkPjhllzJh2hBXeSkBV4fg5O95ci6UUHVvwLsL_CeNpBbraUsYQfPPlb7ZMVGLYz0eBl_CKGHONZ9atFmbYL_ZmtcbX0d1ItHRQzoZnAsqWtzdPw7mjaOj8Me40BmLclGs2sZsa8Dn5pcrHExiDGfu1cUM3xZvmdax0TMaSX5z91lB8_nSDV6hJ0IA3qWF95Xwq7aDfkI63dIDbKpYOc_u0wKDO0rVnk-WFfla2FDAU2TYDsEgJeBzH9kc1KEHmEdnmpVkrUY46oyTSpA.I8IjDxf1r15-nUOugLRFAg";

        let extracted_header = extract_jwe_header(jwe).unwrap();
        assert_eq!(expected_header, extracted_header);

        let decrypted_payload_bytes =
            decrypt_jwe_payload(jwe, PRIVATE_JWK_ED25519.to_string().into()).unwrap();
        assert_eq!(
            Base64UrlSafeNoPadding::encode_to_string(decrypted_payload_bytes).unwrap(),
            expected_payload
        )
    }

    #[test]
    fn test_jwe_round_trip_ec() {
        let payload = b"test_payload";
        let header = Header {
            key_id: "eec37767-ad74-47c9-a349-d95a1bd241d4".to_string(),
            agreement_partyuinfo:
                "\u{18}G\u{7}Ëcr\u{5}Þ§ù\u{97}~Ê0W>9FÖ=\u{17}¹v\u{7f}®ô\u{c}h\u{1c}u\u{99}Ç"
                    .to_string(),
            agreement_partyvinfo: "bueFnxmWT1EJEmPB5zq4m6aqkhEjIN8j".to_string(),
        };

        // shared_secret and remote_jwk were generated from this recipient_jwk
        // let recipient_jwk = RemoteJwk {
        //     kty: "EC".to_string(),
        //     crv: "P-256".to_string(),
        //     x: "KRJIXU-pyEcHURRRQ54jTh9PTTmBYog57rQD1uCsvwo".to_string(),
        //     y: Some("d31DZcRSqaxAUGBt70HB7uCZdufA6uKdL6BvAzUhbJU".to_string()),
        // };

        let shared_secret: Zeroizing<Vec<u8>> = Zeroizing::new(vec![
            185, 127, 8, 220, 210, 43, 60, 110, 151, 231, 212, 11, 160, 247, 208, 50, 2, 70, 29,
            59, 74, 15, 220, 210, 56, 58, 108, 68, 29, 73, 222, 66,
        ]);
        let remote_jwk = RemoteJwk {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "Fo4TzyDJOu5SGMnJx0en6u1EmRkUWCwvhS3BOA8UOqo".to_string(),
            y: Some("J9BMexfC9wE_3-E5Z-EbDFUKEIMwBOBReKT9bEx2KdU".to_string()),
        };

        let jwe = build_jwe(payload, header.clone(), shared_secret, remote_jwk).unwrap();
        let extracted_header = extract_jwe_header(&jwe).unwrap();
        assert_eq!(header, extracted_header);

        let decrypted_payload_bytes =
            decrypt_jwe_payload(&jwe, PRIVATE_JWK_EC.to_string().into()).unwrap();
        assert_eq!(payload.as_slice(), decrypted_payload_bytes);
    }

    #[test]
    fn test_jwe_round_trip_eddsa() {
        let payload = b"test_payload";
        let header = Header {
            key_id: "9be052ed-83b8-4c60-ab4f-214fe21caa93".to_string(),
            agreement_partyuinfo: "BJ\"ûzw\u{11}\u{93}\u{7}Ç>»Ý%\nÁk&âÌÕ°\u{6}\u{9e}Õ_\u{8a}Ö%#Za"
                .to_string(),
            agreement_partyvinfo: "e4xmMaGk6O2UX25eq7Opc46LU7PdzUXp".to_string(),
        };

        // shared_secret and remote_jwk were generated from this recipient_jwk
        // let recipient_jwk = RemoteJwk {
        //     kty: "OKP".to_string(),
        //     crv: "Ed25519".to_string(),
        //     x: "0yErlKcMCx5DG6zmgoUnnFvLBEQuuYWQSYILwV2O9TM".to_string(),
        //     y: None,
        // };

        let shared_secret: Zeroizing<Vec<u8>> = Zeroizing::new(vec![
            15, 180, 14, 191, 235, 127, 224, 178, 119, 167, 9, 251, 183, 199, 13, 60, 54, 14, 104,
            238, 55, 240, 60, 67, 165, 233, 126, 97, 200, 236, 182, 114,
        ]);
        let remote_jwk = RemoteJwk {
            kty: "OKP".to_string(),
            crv: "X25519".to_string(),
            x: "RIAzhfGXIA-OtO-0fWhNKykMRNn8n14US7otIAN_eSM".to_string(),
            y: None,
        };

        let jwe = build_jwe(payload, header.clone(), shared_secret, remote_jwk).unwrap();
        let extracted_header = extract_jwe_header(&jwe).unwrap();
        assert_eq!(header, extracted_header);

        let decrypted_payload_bytes =
            decrypt_jwe_payload(&jwe, PRIVATE_JWK_ED25519.to_string().into()).unwrap();
        assert_eq!(payload.as_slice(), decrypted_payload_bytes);
    }
}
