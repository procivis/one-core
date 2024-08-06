use ciborium::cbor;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::provider::credential_formatter::mdoc_formatter::mdoc::{Bstr, Bytes};

use super::common::EReaderKey;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionEstablishment {
    pub(crate) e_reader_key: Bytes<EReaderKey>,
    pub(crate) data: Bstr,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct SessionData {
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

// SessionTranscript = [
//  DeviceEngagementBytes,
//  EReaderKeyBytes,
//  Handover = null for QRHandover
//]
#[derive(Debug, PartialEq, Clone)]
pub struct SessionTranscript {
    pub(crate) device_engagement_bytes: Bstr,
    pub(crate) e_reader_key_bytes: Bstr,
}

impl Serialize for SessionTranscript {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        cbor!([self.device_engagement_bytes, self.e_reader_key_bytes, null])
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

#[cfg(test)]
mod test {
    use uuid::Uuid;

    use crate::provider::exchange_protocol::iso_mdl::{
        common::{EDeviceKey, KeyAgreement},
        device_engagement::{
            BleOptions, DeviceEngagement, DeviceRetrievalMethod, RetrievalOptions, Security,
        },
    };

    use super::*;

    #[test]
    fn test_session_establishment_serialization() {
        let reader_key = KeyAgreement::<EReaderKey>::new();
        let session_establishment = SessionEstablishment {
            e_reader_key: Bytes(reader_key.reader_key().clone()),
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
            device_engagement_bytes: Bytes(DeviceEngagement {
                security: Security {
                    key_bytes: Bytes(device_key.device_key().clone()),
                },
                device_retrieval_methods: vec![DeviceRetrievalMethod {
                    retrieval_options: RetrievalOptions::Ble(BleOptions {
                        peripheral_server_uuid: Uuid::new_v4(),
                        peripheral_server_mac_address: None,
                    }),
                }],
            })
            .to_cbor_bytes()
            .map(Bstr)
            .unwrap(),
            e_reader_key_bytes: Bytes(reader_key.reader_key().clone())
                .to_cbor_bytes()
                .map(Bstr)
                .unwrap(),
        };

        let mut writer = vec![];
        ciborium::into_writer(&session_transcript, &mut writer).unwrap();

        let value: ciborium::Value = ciborium::from_reader(&writer[..]).unwrap();
        let value = value.into_array().unwrap();

        assert_eq!(
            session_transcript.device_engagement_bytes,
            value[0].deserialized().unwrap()
        );

        assert_eq!(
            session_transcript.e_reader_key_bytes,
            value[1].deserialized().unwrap()
        );

        assert_eq!(ciborium::Value::Null, value[2]);
    }
}
