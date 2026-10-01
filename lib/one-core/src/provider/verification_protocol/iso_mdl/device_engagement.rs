use std::convert::TryInto;

use ciborium::cbor;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{Deserialize, Serialize, Serializer, de, ser};
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum::Display;
use uuid::Uuid;

use super::common::EphemeralSessionKey;
use super::nfc::{BLE_RECORD_TYPE, BLECarrierConfigurationRecord, DEVICE_ENGAGMENT_RECORD_TYPE};
use crate::provider::credential_formatter::mdoc_formatter::util::{Bstr, EmbeddedCbor, MDLVersion};
use crate::provider::presentation_formatter::mso_mdoc::session_transcript::nfc::NFCHandover;
use crate::provider::verification_protocol::error::VerificationProtocolError;

/// ISO 18013-5, 8.2.1.1
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeviceEngagement {
    pub version: MDLVersion<1, 0>,
    pub security: Security,
    // empty vector means missing entry in CBOR
    pub device_retrieval_methods: Vec<DeviceRetrievalMethod>,
    // ServerRetrievalMethods and ProtocolInfo ignored/not implemented
}

/// ISO 18013-5, 8.2.1.1
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Security {
    V1 {
        e_device_key_bytes: EmbeddedCbor<EphemeralSessionKey>,
    },
}

impl Security {
    pub(crate) fn e_device_key_bytes(&self) -> &EmbeddedCbor<EphemeralSessionKey> {
        match &self {
            Self::V1 { e_device_key_bytes } => e_device_key_bytes,
        }
    }
}

/// ISO 18013-5, Table 7
#[expect(clippy::upper_case_acronyms)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq, Display)]
#[repr(u8)]
enum DeviceRetrievalType {
    NFC = 1,
    BLE = 2,
    WifiAware = 3,
}

/// ISO 18013-5, 8.2.1.1
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum DeviceRetrievalMethod {
    BleV1(BleOptionsV1),
    // WifiOptions and NfcOptions not implemented
}

/// ISO 18013-5, 8.2.2.3
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BleOptionsV1 {
    /// filled when peripheral server mode supported
    pub peripheral_server_uuid: Option<Uuid>,

    /// filled when central client mode supported
    pub central_client_uuid: Option<Uuid>,

    /// optional when peripheral server mode supported
    pub peripheral_server_mac_address: Option<String>,
}

/// ISO 18013-5, 8.2.2.3
const QR_CODE_PREFIX: &str = "mdoc:";

impl DeviceEngagement {
    pub(crate) fn into_cbor(self) -> Result<EmbeddedCbor<Self>, VerificationProtocolError> {
        EmbeddedCbor::new(self).map_err(Into::into)
    }

    pub(crate) fn parse_qr_code(
        qr_code_content: &str,
    ) -> Result<EmbeddedCbor<DeviceEngagement>, VerificationProtocolError> {
        if !qr_code_content.starts_with(QR_CODE_PREFIX) {
            return Err(VerificationProtocolError::Failed(format!(
                "Invalid mdoc QR: {qr_code_content}"
            )));
        }

        let data =
            Base64UrlSafeNoPadding::decode_to_vec(&qr_code_content[QR_CODE_PREFIX.len()..], None)?;

        EmbeddedCbor::<DeviceEngagement>::from_raw_cbor(data)
    }

    // currently only NFC static handover supported
    pub(crate) fn parse_nfc(
        nfc_select_message: &str,
    ) -> Result<
        (
            EmbeddedCbor<DeviceEngagement>,
            NFCHandover,
            DeviceRetrievalMethod,
        ),
        VerificationProtocolError,
    > {
        let select_message = Base64UrlSafeNoPadding::decode_to_vec(nfc_select_message, None)?;
        let ndef_message = ndef_rs::NdefMessage::decode(&select_message)
            .map_err(VerificationProtocolError::Other)?;

        let device_engagement_record = ndef_message
            .records()
            .iter()
            .find(|record| record.record_type() == DEVICE_ENGAGMENT_RECORD_TYPE)
            .ok_or(VerificationProtocolError::Failed(
                "Device engagement NDEF record not found".to_string(),
            ))?;
        let device_engagement_cbor = device_engagement_record.payload().to_vec();

        let ble: BLECarrierConfigurationRecord = ndef_message
            .records()
            .iter()
            .find(|record| record.record_type() == BLE_RECORD_TYPE)
            .ok_or(VerificationProtocolError::Failed(
                "BLE NDEF record not found".to_string(),
            ))?
            .try_into()?;

        Ok((
            EmbeddedCbor::<DeviceEngagement>::from_raw_cbor(device_engagement_cbor)?,
            NFCHandover {
                select_message: Bstr(select_message),
                request_message: None,
            },
            DeviceRetrievalMethod::BleV1(BleOptionsV1 {
                peripheral_server_uuid: ble.peripheral_service_uuid(),
                peripheral_server_mac_address: ble
                    .peripheral_mac_address()
                    .as_ref()
                    .map(deserialize_mac_address),
                central_client_uuid: ble.central_service_uuid(),
            }),
        ))
    }
}

impl EmbeddedCbor<DeviceEngagement> {
    fn from_raw_cbor(cbor_data: Vec<u8>) -> Result<Self, VerificationProtocolError> {
        let tagged_value = ciborium::tag::Required::<_, 24>(Bstr(cbor_data));
        let mut bytes: Vec<u8> = vec![];
        ciborium::into_writer(&tagged_value, &mut bytes)?;
        Ok(ciborium::from_reader(bytes.as_slice())?)
    }

    pub(crate) fn generate_qr_code(&self) -> Result<String, VerificationProtocolError> {
        let ciborium::tag::Required::<_, 24>(Bstr(embedded_cbor)) =
            ciborium::from_reader(self.bytes())?;

        let qr_code_content = Base64UrlSafeNoPadding::encode_to_string(&embedded_cbor)
            .map(|content| format!("{QR_CODE_PREFIX}{content}"))?;
        Ok(qr_code_content)
    }
}

impl Serialize for DeviceEngagement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut entries = vec![
            (0.into(), cbor!(self.version).map_err(ser::Error::custom)?),
            (1.into(), cbor!(self.security).map_err(ser::Error::custom)?),
        ];
        if !self.device_retrieval_methods.is_empty() {
            entries.push((
                2.into(),
                cbor!(self.device_retrieval_methods).map_err(ser::Error::custom)?,
            ));
        }

        ciborium::Value::Map(entries).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceEngagement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = ciborium::Value::deserialize(deserializer)?
            .into_map()
            .map_err(|_| de::Error::custom("Invalid DeviceEngagement"))?;

        let version = get_cbor_map_value(&map, 0)
            .ok_or(de::Error::custom("Missing DeviceEngagement version"))?
            .deserialized()
            .map_err(|err| de::Error::custom(format!("Invalid DeviceEngagement version: {err}")))?;

        let security = get_cbor_map_value(&map, 1)
            .ok_or(de::Error::custom("Missing DeviceEngagement security"))?
            .deserialized()
            .map_err(|err| de::Error::custom(format!("Invalid Security: {err}")))?;

        let device_retrieval_methods = if let Some(value) = get_cbor_map_value(&map, 2) {
            value.to_owned().into_array().map_err(|_| {
                de::Error::custom("Invalid DeviceEngagement device_retrieval_methods")
            })?
        } else {
            vec![]
        };

        Ok(DeviceEngagement {
            version,
            security,
            device_retrieval_methods: device_retrieval_methods
                .into_iter()
                .filter_map(|method| {
                    method
                        .deserialized::<DeviceRetrievalMethod>()
                        .inspect_err(|err| {
                            tracing::info!(%err, "Unrecognized/unsupported retrieval method");
                        })
                        .ok()
                })
                .collect(),
        })
    }
}

impl Serialize for Security {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self {
            Self::V1 { e_device_key_bytes } => cbor!([1, e_device_key_bytes])
                .map_err(ser::Error::custom)?
                .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Security {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Tuple((u8, ciborium::Value));

        let Tuple((version, key_bytes)) = Tuple::deserialize(deserializer)?;

        match version {
            1 => Ok(Self::V1 {
                e_device_key_bytes: key_bytes.deserialized().map_err(de::Error::custom)?,
            }),
            other => Err(de::Error::custom(format!(
                "Unsupported Security version: {other}"
            ))),
        }
    }
}

impl Serialize for DeviceRetrievalMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self {
            Self::BleV1(options) => {
                cbor!([DeviceRetrievalType::BLE, 1u8, options])
            }
        }
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceRetrievalMethod {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct Tuple((DeviceRetrievalType, u8, ciborium::Value));

        let Tuple((r#type, version, options)) = Tuple::deserialize(deserializer)?;

        match r#type {
            DeviceRetrievalType::BLE => match version {
                1 => Ok(Self::BleV1(options.deserialized().map_err(|err| {
                    de::Error::custom(format!("Invalid BleOptions: {err}"))
                })?)),
                other => Err(de::Error::custom(format!(
                    "Unsupported BLE options version: {other}"
                ))),
            },
            unsupported => Err(de::Error::custom(format!(
                "Unsupported DeviceRetrievalMethod type: {unsupported}"
            ))),
        }
    }
}

impl Serialize for BleOptionsV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let peripheral_server_mode_supported = self.peripheral_server_uuid.is_some();
        let central_client_mode_supported = self.central_client_uuid.is_some();

        let mut data = cbor!({
            0 => peripheral_server_mode_supported,
            1 => central_client_mode_supported,
        })
        .map_err(ser::Error::custom)?;

        let data_ref = data
            .as_map_mut()
            .ok_or(ser::Error::custom("data map is not a map"))?;

        if let Some(peripheral_server_uuid) = &self.peripheral_server_uuid {
            data_ref.push((
                10.into(),
                ciborium::Value::Bytes(peripheral_server_uuid.into_bytes().to_vec()),
            ));
        }

        if let Some(central_client_uuid) = &self.central_client_uuid {
            data_ref.push((
                11.into(),
                ciborium::Value::Bytes(central_client_uuid.into_bytes().to_vec()),
            ));
        }

        if let Some(peripheral_server_mac_address) = &self.peripheral_server_mac_address {
            let address: Vec<u8> =
                serialize_mac_address::<S>(peripheral_server_mac_address)?.into();
            data.as_map_mut()
                .ok_or(ser::Error::custom("data map is not a map"))?
                .push((20.into(), ciborium::Value::Bytes(address)));
        }

        data.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BleOptionsV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = ciborium::Value::deserialize(deserializer)?
            .into_map()
            .map_err(|_| de::Error::custom("Invalid BleOptions"))?;

        let peripheral_server_mode_supported: bool = get_cbor_map_value(&map, 0)
            .ok_or(de::Error::custom(
                "Missing BleOptions peripheral_server_mode_supported",
            ))?
            .deserialized()
            .map_err(de::Error::custom)?;

        let central_client_mode_supported: bool = get_cbor_map_value(&map, 1)
            .ok_or(de::Error::custom(
                "Missing BleOptions central_client_mode_supported",
            ))?
            .deserialized()
            .map_err(de::Error::custom)?;

        if !peripheral_server_mode_supported && !central_client_mode_supported {
            return Err(de::Error::custom("Invalid BleOptions: no mode supported"));
        }

        let mut result = Self {
            peripheral_server_uuid: None,
            peripheral_server_mac_address: None,
            central_client_uuid: None,
        };

        if peripheral_server_mode_supported {
            let peripheral_server_uuid = get_cbor_map_value(&map, 10)
                .ok_or(de::Error::custom(
                    "Missing BleOptions peripheral_server_uuid",
                ))?
                .to_owned()
                .into_bytes()
                .map_err(|_| de::Error::custom("Invalid BleOptions peripheral_server_uuid"))?
                .try_into()
                .map_err(|_| de::Error::custom("Invalid BleOptions peripheral_server_uuid"))?;
            result.peripheral_server_uuid = Some(Uuid::from_bytes(peripheral_server_uuid));

            if let Some(peripheral_server_mac_address) = get_cbor_map_value(&map, 20) {
                let bytes = peripheral_server_mac_address
                    .to_owned()
                    .into_bytes()
                    .map_err(|_| {
                        de::Error::custom("Invalid BleOptions peripheral_server_mac_address")
                    })?
                    .try_into()
                    .map_err(|_| {
                        de::Error::custom("Invalid BleOptions peripheral_server_mac_address")
                    })?;
                result.peripheral_server_mac_address = Some(deserialize_mac_address(&bytes));
            }
        }

        if central_client_mode_supported {
            let central_client_uuid = get_cbor_map_value(&map, 11)
                .ok_or(de::Error::custom("Missing BleOptions central_client_uuid"))?
                .to_owned()
                .into_bytes()
                .map_err(|_| de::Error::custom("Invalid BleOptions central_client_uuid"))?
                .try_into()
                .map_err(|_| de::Error::custom("Invalid BleOptions central_client_uuid"))?;
            result.central_client_uuid = Some(Uuid::from_bytes(central_client_uuid));
        }

        Ok(result)
    }
}

fn serialize_mac_address<S>(mac: &str) -> Result<[u8; 6], S::Error>
where
    S: Serializer,
{
    let data = mac
        .split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ser::Error::custom)?;

    data.try_into()
        .map_err(|_| ser::Error::custom("Invalid MAC address"))
}

fn deserialize_mac_address(mac: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn get_cbor_map_value(
    map: &[(ciborium::Value, ciborium::Value)],
    key: i8,
) -> Option<&ciborium::Value> {
    let value = map
        .iter()
        .find(|(k, _)| k.as_integer().is_some_and(|val| val == key.into()));

    value.map(|(_, v)| v)
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use similar_asserts::assert_eq;
    use uuid::uuid;

    use super::*;
    use crate::provider::key_algorithm::eddsa::Eddsa;
    use crate::provider::verification_protocol::iso_mdl::common::KeyAgreementKey;

    #[test]
    fn test_device_engagement_serialization() {
        let engagment = get_example_engagement();

        let mut data: Vec<u8> = vec![];
        ciborium::into_writer(&engagment, &mut data).unwrap();

        let decoded: DeviceEngagement = ciborium::from_reader(&data[..]).unwrap();
        assert_eq!(engagment, decoded);
    }

    #[test]
    fn test_device_engagement_qr_code() {
        let engagement = get_example_engagement();

        let cbor_device_engagement = engagement.clone().into_cbor().unwrap();
        let qr_code_content = cbor_device_engagement.generate_qr_code().unwrap();
        let parsed = DeviceEngagement::parse_qr_code(&qr_code_content).unwrap();

        assert_eq!(&engagement, parsed.inner());
        assert_eq!(cbor_device_engagement, parsed);
        assert_eq!(cbor_device_engagement.into_bytes(), parsed.into_bytes());
    }

    #[test]
    fn test_device_engagement_deserialize_iso_example() {
        // ISO 18013-5, D.3.1
        let data = hex!(
            r#"a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d9
               3e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32
               fc670281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917"#
        )
        .to_vec();

        let parsed = ciborium::from_reader::<DeviceEngagement, _>(&data[..]).unwrap();
        assert_eq!(parsed.version, MDLVersion::<1, 0>::default());
        assert_eq!(
            parsed.device_retrieval_methods,
            vec![DeviceRetrievalMethod::BleV1(BleOptionsV1 {
                peripheral_server_uuid: None,
                peripheral_server_mac_address: None,
                central_client_uuid: Some(uuid!("45efef74-2b2c-4837-a9a3-b0e1d05a6917")),
            })]
        );
    }

    #[test]
    fn test_device_engagement_parse_nfc() {
        let select_message = hex!("9c1e510469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a30063312e30018201d8185828a30101200421582058ab3a35f030c957dbcae8062bf10768a83b80e5ca0b89b9d945b43812c0113a0281830201a300f501f40a509dbd8e030e73412d979324552b59970a110211487315d1020b61630103424c4501046d646f635a2015036170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f62424c45021c0011070a97592b552493972d41730e038ebd9d"
        )
        .to_vec();
        let (_device_engagement, handover, device_retrieval_method) = DeviceEngagement::parse_nfc(
            &Base64UrlSafeNoPadding::encode_to_string(&select_message).unwrap(),
        )
        .unwrap();
        assert_eq!(handover.select_message.0, select_message);
        assert_eq!(handover.request_message, None);

        assert_eq!(
            device_retrieval_method,
            DeviceRetrievalMethod::BleV1(BleOptionsV1 {
                peripheral_server_uuid: Some(uuid!("9dbd8e03-0e73-412d-9793-24552b59970a")),
                peripheral_server_mac_address: None,
                central_client_uuid: None
            }),
        );
    }

    #[test]
    fn test_device_engagement_nfc_iso_example() {
        // ISO 18013-5, D.3.3 - handover select message during negotiated handover
        let data = hex!(
            "91020f487315d10209616301013001046d646f631a200c016170706c69636174696f6e2f766e642e626c756574\
             6f6f74682e6c652e6f6f6230081b28128b37282801021c015c1e580469736f2e6f72673a31383031333a646576\
             696365656e676167656d656e746d646f63a20063312e30018201d818584ba4010220012158205a88d182bce5f4\
             2efa59943f33359d2e8a968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8\
             cfcf3de6aa672fc60a557aa32fc67"
        )
        .to_vec();

        // failing: negotiated handover select message does not include service UUID
        let failure =
            DeviceEngagement::parse_nfc(&Base64UrlSafeNoPadding::encode_to_string(data).unwrap())
                .unwrap_err();
        assert!(failure.to_string().contains("Missing service uuid"));
    }

    fn get_example_engagement() -> DeviceEngagement {
        let ka_device = KeyAgreementKey::generate(&Eddsa).unwrap();

        DeviceEngagement {
            version: Default::default(),
            security: Security::V1 {
                e_device_key_bytes: EmbeddedCbor::new(ka_device.ephemeral_key().to_owned())
                    .unwrap(),
            },
            device_retrieval_methods: vec![DeviceRetrievalMethod::BleV1(BleOptionsV1 {
                peripheral_server_uuid: Some(uuid!("18c39646-2c91-43d6-b0c7-8cc86efd2573")),
                peripheral_server_mac_address: Some("F6:AC:82:54:69:B7".to_string()),
                central_client_uuid: None,
            })],
        }
    }
}
