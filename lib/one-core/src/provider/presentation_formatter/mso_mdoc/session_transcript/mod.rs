use ciborium::cbor;
use serde::{Deserialize, Serialize, Serializer, de, ser};

use self::iso_18013_7::OID4VPDraftHandover;
use self::nfc::NFCHandover;
use self::openid4vp_final1_0::OID4VPFinal1_0Handover;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::verification_protocol::iso_mdl::common::EReaderKey;
use crate::provider::verification_protocol::iso_mdl::device_engagement::DeviceEngagement;

pub mod iso_18013_7;
pub mod nfc;
pub mod openid4vp_final1_0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Handover {
    Iso18013_7AnnexB(OID4VPDraftHandover),
    OID4VPFinal1_0(OID4VPFinal1_0Handover),
    Nfc(NFCHandover),
    // QR-code handover is null (implemented as missing handover)
}

/// ISO 18013-5 9.1.5.1 Session transcript
///
/// `SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ]`
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionTranscript {
    pub device_engagement_bytes: Option<EmbeddedCbor<DeviceEngagement>>,
    pub e_reader_key_bytes: Option<EmbeddedCbor<EReaderKey>>,
    pub handover: Option<Handover>,
}

impl Serialize for SessionTranscript {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([
            self.device_engagement_bytes,
            self.e_reader_key_bytes,
            self.handover
        ])
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

impl<'a> Deserialize<'a> for SessionTranscript {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'a>,
    {
        let (device_engagement_bytes, e_reader_key_bytes, handover) =
            ciborium::Value::deserialize(deserializer)?
                .deserialized()
                .map_err(de::Error::custom)?;

        Ok(Self {
            device_engagement_bytes,
            e_reader_key_bytes,
            handover,
        })
    }
}
