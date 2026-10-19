use ciborium::cbor;
use coset::CborSerializable;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use sha2::{Digest, Sha256};
use standardized_types::jwk::PublicJwk;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;

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
        verifier_key: Option<&PublicJwk>,
    ) -> Result<Self, FormatterError> {
        let client_id = client_id.trim_end_matches('/');
        let response_uri = response_uri.trim_end_matches('/');
        let jwk_thumbprint = verifier_key
            .map(PublicJwk::thumbprint)
            .transpose()?
            .map(Bstr);

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

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use similar_asserts::assert_eq;
    use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};

    use super::OID4VPFinal1_0Handover;
    use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
        Handover, SessionTranscript,
    };

    #[tokio::test]
    async fn test_oid4vp_handover_compute_against_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1-11
        let expected_handover_bytes = hex!(
            "82714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
        );

        let jwk = PublicJwk::Ec(PublicJwkEc {
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

    #[tokio::test]
    async fn test_oid4vp_session_transcript_against_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1-13
        let transcript = hex!(
            "83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac"
        );
        let transcript: SessionTranscript = ciborium::from_reader(transcript.as_slice()).unwrap();
        assert!(transcript.device_engagement_bytes.is_none());
        assert!(transcript.e_reader_key_bytes.is_none());

        match transcript.handover {
            Handover::OID4VPFinal1_0(handover) => assert_eq!(
                handover.openid4vp_handover_info_hash.0,
                hex!("048bc053c00442af9b8eed494cefdd9d95240d254b046b11b68013722aad38ac")
            ),
            other => panic!("Expected Some(OID4VPFinal1_0Handover), got {:?}", other),
        };
    }
}
