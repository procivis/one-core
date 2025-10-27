use anyhow::anyhow;
use ciborium::cbor;
use serde::{Deserialize, Serialize, Serializer, de, ser};
use sha2::{Digest, Sha256};

use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;

/// ISO 18013-7 Annex B OpenID4VP Handover structure
///
/// B.4.4: `OID4VPHandover = [ clientIdHash, responseUriHash, nonce ]`
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OID4VPDraftHandover {
    client_id_hash: Bstr,
    response_uri_hash: Bstr,
    nonce: String,
}

impl OID4VPDraftHandover {
    pub(crate) fn compute(
        client_id: &str,
        response_uri: &str,
        nonce: &str,
        mdoc_generated_nonce: &str,
    ) -> Result<Self, anyhow::Error> {
        let client_id = client_id.trim_end_matches('/');
        let response_uri = response_uri.trim_end_matches('/');

        let client_id_to_hash = [client_id, mdoc_generated_nonce];
        let response_uri_to_hash = [response_uri, mdoc_generated_nonce];

        let client_id_hash = compute_hash(&client_id_to_hash)?;
        let response_uri_hash = compute_hash(&response_uri_to_hash)?;

        Ok(Self {
            client_id_hash,
            response_uri_hash,
            nonce: nonce.to_owned(),
        })
    }
}

/// compute SHA-256 hash
fn compute_hash(values_to_hash: &[&str]) -> Result<Bstr, anyhow::Error> {
    let cbor_value = cbor!(values_to_hash).map_err(|e| anyhow!("CBOR error: {}", e))?;

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&cbor_value, &mut buf)
        .map_err(|e| anyhow!("CBOR serialization error: {}", e))?;

    Ok(Bstr(Sha256::digest(&buf).to_vec()))
}

impl Serialize for OID4VPDraftHandover {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([self.client_id_hash, self.response_uri_hash, self.nonce])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for OID4VPDraftHandover {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (client_id_hash, response_uri_hash, nonce) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        Ok(Self {
            client_id_hash,
            response_uri_hash,
            nonce,
        })
    }
}
