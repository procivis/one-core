use ciborium::cbor;
use serde::{Deserialize, Serialize, Serializer, de, ser};

use self::dc_api::DcApiHandover;
use self::nfc::NFCHandover;
use self::openid4vp_final1_0::OID4VPFinal1_0Handover;
use self::qr_code::QRHandover;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;
use crate::provider::verification_protocol::iso_mdl::common::EphemeralSessionKey;
use crate::provider::verification_protocol::iso_mdl::device_engagement::DeviceEngagement;

pub mod dc_api;
pub mod nfc;
pub mod openid4vp_final1_0;
pub mod qr_code;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum Handover {
    OID4VPFinal1_0(OID4VPFinal1_0Handover),
    QrCode(QRHandover),
    Nfc(NFCHandover),
    DcApi(DcApiHandover),
}

/// ISO 18013-5 9.1.5.1 Session transcript
///
/// `SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ]`
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct SessionTranscript {
    pub device_engagement_bytes: Option<EmbeddedCbor<DeviceEngagement>>,
    pub e_reader_key_bytes: Option<EmbeddedCbor<EphemeralSessionKey>>,
    pub handover: Handover,
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

#[cfg(test)]
mod tests {
    use assert2::let_assert;
    use hex_literal::hex;
    use similar_asserts::assert_eq;

    use super::{Handover, SessionTranscript};
    use crate::provider::credential_formatter::mdoc_formatter::util::{EmbeddedCbor, MDLVersion};
    use crate::provider::presentation_formatter::mso_mdoc::session_transcript::nfc::NFCHandover;

    #[tokio::test]
    async fn test_session_transcript_against_test_vector() {
        // ISO 18013-5, D.5.1
        let transcript_bytes = hex!(
            r#"d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88
d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d
4c338237a8cfcf3de6aa672fc60a557aa32fc67d818584ba40102200121582060e3392385041f51403051f2415
531cb56dd3f999c71687013aac6768bc8187e225820e58deb8fdbe907f7dd5368245551a34796f7d2215c440c3
39bb0f7b67beccdfa8258c391020f487315d10209616301013001046d646f631a200c016170706c69636174696
f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f7
2673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba401022
0012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858dd
c7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd9102254872159102026372010211020461
6301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e
626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d48
23a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e6
42e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc
35e700a6b020414"#
        );
        let transcript: EmbeddedCbor<SessionTranscript> =
            ciborium::from_reader(transcript_bytes.as_slice()).unwrap();

        let transcript = transcript.into_inner();
        let device_engagement = transcript.device_engagement_bytes.unwrap().into_inner();
        assert_eq!(device_engagement.version, MDLVersion::<1, 0>::default());
        assert_eq!(device_engagement.device_retrieval_methods, vec![]);

        assert!(transcript.e_reader_key_bytes.is_some());

        let_assert!(
            Handover::Nfc(NFCHandover {
                select_message,
                request_message,
            }) = transcript.handover
        );
        assert_eq!(
            select_message.0,
            hex!(
                "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc67"
            )
        );
        assert_eq!(
            request_message.unwrap().0,
            hex!(
                "91022548721591020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34dfcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f766e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e700a6b020414"
            )
        );
    }
}
