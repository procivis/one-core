use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::common::EReaderKey;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{Bstr, EmbeddedCbor};

#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub enum Command {
    Start = 1,
    End = 2,
}

impl TryFrom<Vec<u8>> for Command {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        match value.as_slice() {
            [1] => Ok(Self::Start),
            [2] => Ok(Self::End),
            [_] => Err(anyhow!("value out of range")),
            _ => Err(anyhow!("invalid payload size")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionEstablishment {
    pub(crate) e_reader_key: EmbeddedCbor<EReaderKey>,
    pub(crate) data: Bstr,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct SessionData {
    pub(crate) data: Option<Bstr>,
    pub(crate) status: Option<StatusCode>,
}

#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
#[repr(u8)]
pub enum StatusCode {
    SessionEncryptionError = 10,
    CborDecodingError = 11,
    SessionTermination = 20,
}

#[cfg(test)]
mod test {
    use uuid::Uuid;

    use super::*;
    use crate::provider::credential_formatter::mdoc_formatter::mdoc::SessionTranscript;
    use crate::provider::exchange_protocol::iso_mdl::common::{EDeviceKey, KeyAgreement};
    use crate::provider::exchange_protocol::iso_mdl::device_engagement::{
        BleOptions, DeviceEngagement, DeviceRetrievalMethod, RetrievalOptions, Security,
    };

    #[test]
    fn test_session_establishment_serialization() {
        let reader_key = KeyAgreement::<EReaderKey>::new();
        let session_establishment = SessionEstablishment {
            e_reader_key: EmbeddedCbor::new(reader_key.reader_key().clone()).unwrap(),
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
        let device_key = KeyAgreement::<EDeviceKey>::new();
        let reader_key = KeyAgreement::<EReaderKey>::new();

        let session_transcript = SessionTranscript {
            device_engagement_bytes: EmbeddedCbor::new(DeviceEngagement {
                security: Security {
                    key_bytes: EmbeddedCbor::new(device_key.device_key().clone()).unwrap(),
                },
                device_retrieval_methods: vec![DeviceRetrievalMethod {
                    retrieval_options: RetrievalOptions::Ble(BleOptions {
                        peripheral_server_uuid: Uuid::new_v4(),
                        peripheral_server_mac_address: None,
                    }),
                }],
            })
            .unwrap()
            .into(),
            e_reader_key_bytes: EmbeddedCbor::new(reader_key.reader_key().clone())
                .unwrap()
                .into(),
            handover: None,
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
