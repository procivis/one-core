use ciborium::cbor;
use coset::CborSerializable;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use sha2::{Digest, Sha256};
use standardized_types::jwk::PublicJwk;

use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;

/// OpenID4VP Digital Credentials API Handover
/// <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.2>
///
/// `OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover",  OpenID4VPDCAPIHandoverInfoHash ]`
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OID4VPDcApiHandover {
    openid4vp_dc_api_handover_info_hash: Bstr,
}

impl OID4VPDcApiHandover {
    #[allow(unused)]
    pub(crate) fn compute(
        origin: &str,
        nonce: &str,
        verifier_key: Option<&PublicJwk>,
    ) -> Result<Self, FormatterError> {
        let jwk_thumbprint = verifier_key
            .map(PublicJwk::thumbprint)
            .transpose()?
            .map(Bstr);

        let openid4vp_dc_api_handover_info_bytes =
            cbor!([origin, nonce, jwk_thumbprint])?.to_vec()?;

        let openid4vp_dc_api_handover_info_hash =
            Bstr(Sha256::digest(&openid4vp_dc_api_handover_info_bytes).to_vec());

        Ok(Self {
            openid4vp_dc_api_handover_info_hash,
        })
    }
}

impl Serialize for OID4VPDcApiHandover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([
            "OpenID4VPDCAPIHandover",
            self.openid4vp_dc_api_handover_info_hash
        ])
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for OID4VPDcApiHandover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (fixed_id, openid4vp_dc_api_handover_info_hash): (String, Bstr) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        if fixed_id != "OpenID4VPDCAPIHandover" {
            return Err(de::Error::custom(format!(
                "Invalid leading identifier: {fixed_id}"
            )));
        }

        Ok(Self {
            openid4vp_dc_api_handover_info_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert2::let_assert;
    use hex_literal::hex;
    use similar_asserts::assert_eq;
    use standardized_types::jwk::{JwkUse, PublicJwk, PublicJwkEc};

    use super::OID4VPDcApiHandover;
    use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
        Handover, SessionTranscript,
    };

    #[test]
    fn test_oid4vp_dc_api_handover_compute_against_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.2-11
        let expected_handover_bytes = hex!(
            "82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
        );

        let jwk = PublicJwk::Ec(PublicJwkEc {
            alg: Some("ES256".to_string()),
            r#use: Some(JwkUse::Encryption),
            kid: Some("1".to_string()),
            crv: "P-256".to_string(),
            x: "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0".to_string(),
            y: Some("XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc".to_string()),
        });

        let handover = OID4VPDcApiHandover::compute(
            "https://example.com",
            "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            Some(&jwk),
        )
        .unwrap();

        let mut s = vec![];
        ciborium::into_writer(&handover, &mut s).unwrap();

        assert_eq!(s, expected_handover_bytes);
    }

    #[test]
    fn test_oid4vp_dcapi_handover_deserialize_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.1-11
        let handover_bytes = hex!(
            "82764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
        );

        let handover: OID4VPDcApiHandover = ciborium::de::from_reader(&handover_bytes[..]).unwrap();

        let expected_handover_info_hash =
            hex!("fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a");
        assert_eq!(
            handover.openid4vp_dc_api_handover_info_hash.0,
            expected_handover_info_hash
        );
    }

    #[test]
    fn test_oid4vp_dcapi_session_transcript_against_test_vector() {
        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.2.6.2-13
        let transcript = hex!(
            "83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a"
        );
        let transcript: SessionTranscript = ciborium::from_reader(transcript.as_slice()).unwrap();
        assert!(transcript.device_engagement_bytes.is_none());
        assert!(transcript.e_reader_key_bytes.is_none());

        let_assert!(Handover::OID4VPDcApi(handover) = transcript.handover);
        assert_eq!(
            handover.openid4vp_dc_api_handover_info_hash.0,
            hex!("fbece366f4212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a")
        );
    }
}
