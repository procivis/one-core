use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, EmbeddedCbor};
use crate::provider::verification_protocol::iso_mdl::common::EphemeralSessionKey;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SessionEstablishment {
    pub(crate) e_reader_key: EmbeddedCbor<EphemeralSessionKey>,
    pub(crate) data: Bstr,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct SessionData {
    pub(crate) data: Option<Bstr>,
    pub(crate) status: Option<StatusCode>,
}

#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub(crate) enum StatusCode {
    SessionEncryptionError = 10,
    CborDecodingError = 11,
    SessionTermination = 20,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::provider::key_algorithm::ecdsa::Ecdsa;
    use crate::provider::presentation_formatter::mso_mdoc::session_transcript::{
        Handover, SessionTranscript,
    };
    use crate::provider::verification_protocol::iso_mdl::common::KeyAgreementKey;
    use crate::provider::verification_protocol::iso_mdl::device_engagement::{
        BleOptionsV1, DeviceEngagement, DeviceRetrievalMethod, Security,
    };

    #[test]
    fn test_session_establishment_serialization() {
        let reader_key = KeyAgreementKey::generate(&Ecdsa).unwrap();
        let session_establishment = SessionEstablishment {
            e_reader_key: EmbeddedCbor::new(reader_key.ephemeral_key().clone()).unwrap(),
            data: Bstr(b"test data".to_vec()),
        };

        let mut writer = vec![];
        ciborium::into_writer(&session_establishment, &mut writer).unwrap();

        assert_eq!(
            session_establishment,
            ciborium::from_reader(&writer[..]).unwrap()
        );
    }

    #[test]
    fn test_session_data_serialization() {
        let session_data = SessionData {
            data: Some(Bstr(b"test data".to_vec())),
            status: Some(StatusCode::SessionTermination),
        };

        let mut writer = vec![];
        ciborium::into_writer(&session_data, &mut writer).unwrap();

        assert_eq!(session_data, ciborium::from_reader(&writer[..]).unwrap());
    }

    #[test]
    fn test_session_transcript_serialization() {
        let device_key = KeyAgreementKey::generate(&Ecdsa).unwrap();
        let reader_key = KeyAgreementKey::generate(&Ecdsa).unwrap();

        let session_transcript = SessionTranscript {
            device_engagement_bytes: EmbeddedCbor::new(DeviceEngagement {
                version: Default::default(),
                security: Security::V1 {
                    e_device_key_bytes: EmbeddedCbor::new(device_key.ephemeral_key().clone())
                        .unwrap(),
                },
                device_retrieval_methods: vec![DeviceRetrievalMethod::BleV1(BleOptionsV1 {
                    peripheral_server_uuid: Some(Uuid::new_v4()),
                    peripheral_server_mac_address: None,
                    central_client_uuid: None,
                })],
            })
            .unwrap()
            .into(),
            e_reader_key_bytes: EmbeddedCbor::new(reader_key.ephemeral_key().clone())
                .unwrap()
                .into(),
            handover: Handover::QrCode(Default::default()),
        };

        let mut writer = vec![];
        ciborium::into_writer(&session_transcript, &mut writer).unwrap();

        let value: ciborium::Value = ciborium::from_reader(&writer[..]).unwrap();
        let value = value.into_array().unwrap();

        let (tag, device_engagement_bytes) = value[0].as_tag().unwrap();
        assert_eq!(24, tag);
        assert_eq!(
            &session_transcript.device_engagement_bytes.unwrap().bytes()[4..],
            device_engagement_bytes.as_bytes().unwrap()
        );

        let (tag, e_reader_key_bytes) = value[1].as_tag().unwrap();
        assert_eq!(24, tag);
        assert_eq!(
            &session_transcript.e_reader_key_bytes.unwrap().bytes()[4..],
            e_reader_key_bytes.as_bytes().unwrap()
        );

        assert_eq!(ciborium::Value::Null, value[2]);
    }
}
