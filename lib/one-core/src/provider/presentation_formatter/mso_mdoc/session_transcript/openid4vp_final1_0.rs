use ciborium::cbor;
use coset::CborSerializable;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use sha2::{Digest, Sha256};

use crate::model::key::PublicKeyJwk;
use crate::util::mdoc::Bstr;

/// OpenID4VP Final Handover
/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1>
///
/// `OpenID4VPHandover = [ "OpenID4VPHandover",  OpenID4VPHandoverInfoHash ]`
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OID4VPFinal1_0Handover {
    openid4vp_handover_info_hash: Bstr,
}

impl OID4VPFinal1_0Handover {
    pub(crate) fn compute(
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        verifier_key: Option<&PublicKeyJwk>,
    ) -> Result<Self, anyhow::Error> {
        let client_id = client_id.trim_end_matches('/');
        let response_uri = response_uri.trim_end_matches('/');
        let jwk_thumbprint = verifier_key.map(jwk_thumbprint).transpose()?.map(Bstr);

        let openid4vp_handover_info_bytes =
            cbor!([client_id, nonce, jwk_thumbprint, response_uri])?.to_vec()?;

        let openid4vp_handover_info_hash =
            Bstr(Sha256::digest(&openid4vp_handover_info_bytes).to_vec());

        Ok(Self {
            openid4vp_handover_info_hash,
        })
    }
}

impl Serialize for OID4VPFinal1_0Handover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!(["OpenID4VPHandover", self.openid4vp_handover_info_hash])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for OID4VPFinal1_0Handover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (fixed_id, openid4vp_handover_info_hash): (String, Bstr) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        if fixed_id != "OpenID4VPHandover" {
            return Err(de::Error::custom(format!(
                "Invalid leading identifier: {fixed_id}"
            )));
        }

        Ok(Self {
            openid4vp_handover_info_hash,
        })
    }
}

/// RFC7638 JWK Thumbprint
/// <https://www.rfc-editor.org/rfc/rfc7638.html>
///
/// - inspired by: <https://docs.rs/biscuit/0.7.0/src/biscuit/jwk.rs.html#276>
/// - using SHA-256 hash function
fn jwk_thumbprint(verifier_key: &PublicKeyJwk) -> Result<Vec<u8>, anyhow::Error> {
    use serde::ser::SerializeMap;

    let mut serializer = serde_json::Serializer::new(Vec::new());
    let mut map = serializer.serialize_map(None)?;
    match verifier_key {
        PublicKeyJwk::Ec(params) => {
            map.serialize_entry("crv", &params.crv)?;
            map.serialize_entry("kty", "EC")?;
            map.serialize_entry("x", &params.x)?;
            map.serialize_entry("y", &params.y)?;
        }
        PublicKeyJwk::Rsa(params) => {
            map.serialize_entry("e", &params.e)?;
            map.serialize_entry("kty", "RSA")?;
            map.serialize_entry("n", &params.n)?;
        }
        PublicKeyJwk::Okp(params) => {
            map.serialize_entry("crv", &params.crv)?;
            map.serialize_entry("kty", "OKP")?;
            map.serialize_entry("x", &params.x)?;
        }
        PublicKeyJwk::Oct(params) => {
            map.serialize_entry("k", &params.k)?;
            map.serialize_entry("kty", "oct")?;
        }
        PublicKeyJwk::Mlwe(params) => {
            map.serialize_entry("alg", &params.alg)?;
            map.serialize_entry("kty", "MLWE")?;
            map.serialize_entry("x", &params.x)?;
        }
    };
    map.end()?;
    Ok(Sha256::digest(serializer.into_inner()).to_vec())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use similar_asserts::assert_eq;

    use super::OID4VPFinal1_0Handover;
    use crate::model::key::{JwkUse, PublicKeyJwk, PublicKeyJwkEllipticData};

    #[tokio::test]
    async fn test_oid4vp_handover_compute_against_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1-11
        let expected_handover_bytes = hex!(
            "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
        );

        let jwk = PublicKeyJwk::Ec(PublicKeyJwkEllipticData {
            alg: Some("ES256".to_string()),
            r#use: Some(JwkUse::Encryption),
            kid: Some("1".to_string()),
            crv: "P-256".to_string(),
            x: "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0".to_string(),
            y: Some("XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc".to_string()),
        });

        let handover = OID4VPFinal1_0Handover::compute(
            "x509_san_dns:example.com",
            "https://example.com/response",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk),
        )
        .unwrap();

        let mut s = vec![];
        ciborium::into_writer(&handover, &mut s).unwrap();

        assert_eq!(s, expected_handover_bytes);
    }

    #[tokio::test]
    async fn test_oid4vp_handover_deserialize_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1-11
        let handover_bytes = hex!(
            "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
        );

        let handover: OID4VPFinal1_0Handover =
            ciborium::de::from_reader(&handover_bytes[..]).unwrap();

        let expected_handover_info_hash =
            hex!("048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac");
        assert_eq!(
            handover.openid4vp_handover_info_hash.0,
            expected_handover_info_hash
        );
    }
}
