use std::convert::TryInto;

use anyhow::{Context, anyhow};
use ciborium::cbor;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use serde::{Deserialize, Serialize, Serializer, de, ser};
use uuid::Uuid;

use super::common::EDeviceKey;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{Bstr, EmbeddedCbor};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeviceEngagement {
    // pub version: DeviceEngagementVersion,
    pub security: Security,
    pub device_retrieval_methods: Vec<DeviceRetrievalMethod>,
    // ServerRetrievalMethods and ProtocolInfo ignored/not implemented
}

const DEVICE_ENGAGEMENT_VERSION: &str = "1.0";

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Security {
    // pub version: i8,
    pub key_bytes: EmbeddedCbor<EDeviceKey>,
}

const SECURITY_VERSION: i8 = 1;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DeviceRetrievalMethod {
    // pub r#type: u8,
    // pub version: u8,
    pub retrieval_options: RetrievalOptions,
}

const RETRIEVAL_METHOD_TYPE_BLE: u8 = 2;
const RETRIEVAL_METHOD_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RetrievalOptions {
    Ble(BleOptions),
    // WifiOptions and NfcOptions not implemented
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BleOptions {
    // pub peripheral_server_mode_supported: bool, // required to be true
    // pub central_client_mode_supported: bool,
    pub peripheral_server_uuid: Uuid,
    // pub client_central_uuid: Uuid,
    pub peripheral_server_mac_address: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct GeneratedQRCode {
    pub qr_code_content: String,
    pub device_engagement: EmbeddedCbor<DeviceEngagement>,
}

impl DeviceEngagement {
    const QR_CODE_PREFIX: &'static str = "mdoc:";

    pub(crate) fn generate_qr_code(self) -> anyhow::Result<GeneratedQRCode> {
        let device_engagement = EmbeddedCbor::new(self)?;

        let ciborium::tag::Required::<_, 24>(Bstr(embedded_cbor)) =
            ciborium::from_reader(device_engagement.bytes())?;

        let qr_code_content = Base64UrlSafeNoPadding::encode_to_string(&embedded_cbor)
            .map(|content| format!("{}{content}", Self::QR_CODE_PREFIX))
            .context("QR code base64 encoding")?;

        Ok(GeneratedQRCode {
            qr_code_content,
            device_engagement,
        })
    }

    pub(crate) fn parse_qr_code(
        qr_code_content: &str,
    ) -> anyhow::Result<EmbeddedCbor<DeviceEngagement>> {
        if !qr_code_content.starts_with(Self::QR_CODE_PREFIX) {
            return Err(anyhow!("Invalid mdoc QR: {qr_code_content}"));
        }

        let data = Base64UrlSafeNoPadding::decode_to_vec(
            &qr_code_content[Self::QR_CODE_PREFIX.len()..],
            None,
        )?;

        let tagged_value = ciborium::tag::Required::<_, 24>(Bstr(data));
        let mut bytes: Vec<u8> = vec![];
        ciborium::into_writer(&tagged_value, &mut bytes)?;

        Ok(ciborium::from_reader(bytes.as_slice())?)
    }
}

impl Serialize for DeviceEngagement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!({
            0 => DEVICE_ENGAGEMENT_VERSION,
            1 => self.security,
            2 => self.device_retrieval_methods
        })
        .map_err(ser::Error::custom)?
        .serialize(serializer)
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
            .ok_or(de::Error::custom("Missing DeviceEngagement version"))?;

        if version
            .as_text()
            .is_none_or(|s| s != DEVICE_ENGAGEMENT_VERSION)
        {
            return Err(de::Error::custom("Invalid DeviceEngagement version"));
        }

        let security = get_cbor_map_value(&map, 1)
            .ok_or(de::Error::custom("Missing DeviceEngagement security"))?;
        let device_retrieval_methods = get_cbor_map_value(&map, 2)
            .ok_or(de::Error::custom(
                "Missing DeviceEngagement device_retrieval_methods",
            ))?
            .to_owned()
            .into_array()
            .map_err(|_| de::Error::custom("Invalid DeviceEngagement device_retrieval_methods"))?;

        Ok(DeviceEngagement {
            security: deserialize_security::<D>(security.to_owned())?,
            device_retrieval_methods: device_retrieval_methods
                .into_iter()
                .map(deserialize_device_retrieval_method::<D>)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl Serialize for Security {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        cbor!([SECURITY_VERSION, self.key_bytes])
            .map_err(ser::Error::custom)?
            .serialize(serializer)
    }
}

fn deserialize_security<'de, D>(value: ciborium::Value) -> Result<Security, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let array = value
        .into_array()
        .map_err(|_| de::Error::custom("Invalid Security"))?;

    if array.len() < 2 {
        return Err(de::Error::custom("Invalid Security"));
    }

    let version = array
        .first()
        .ok_or(de::Error::custom("Missing Security version"))?;
    if version
        .as_integer()
        .is_none_or(|v| v != SECURITY_VERSION.into())
    {
        return Err(de::Error::custom("Invalid Security version"));
    }

    let key_bytes = array
        .get(1)
        .ok_or(de::Error::custom("Missing Security key_bytes"))?
        .to_owned();

    Ok(Security {
        key_bytes: key_bytes.deserialized().map_err(de::Error::custom)?,
    })
}

impl Serialize for DeviceRetrievalMethod {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match &self.retrieval_options {
            RetrievalOptions::Ble(options) => {
                cbor!([RETRIEVAL_METHOD_TYPE_BLE, RETRIEVAL_METHOD_VERSION, options])
            }
        }
        .map_err(ser::Error::custom)?
        .serialize(serializer)
    }
}

fn deserialize_device_retrieval_method<'de, D>(
    value: ciborium::Value,
) -> Result<DeviceRetrievalMethod, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let array = value
        .into_array()
        .map_err(|_| de::Error::custom("Invalid DeviceRetrievalMethod"))?;

    if array.len() < 3 {
        return Err(de::Error::custom("Invalid DeviceRetrievalMethod"));
    }

    let r#type = array
        .first()
        .ok_or(de::Error::custom("Missing DeviceRetrievalMethod type"))?;
    if r#type
        .as_integer()
        .is_none_or(|v| v != RETRIEVAL_METHOD_TYPE_BLE.into())
    {
        return Err(de::Error::custom("Invalid DeviceRetrievalMethod type"));
    }

    let version = array
        .get(1)
        .ok_or(de::Error::custom("Missing DeviceRetrievalMethod version"))?;
    if version
        .as_integer()
        .is_none_or(|v| v != RETRIEVAL_METHOD_VERSION.into())
    {
        return Err(de::Error::custom("Invalid DeviceRetrievalMethod version"));
    }

    let options = array
        .get(2)
        .ok_or(de::Error::custom("Missing DeviceRetrievalMethod options"))?;

    Ok(DeviceRetrievalMethod {
        retrieval_options: RetrievalOptions::Ble(deserialize_ble_options::<D>(options.to_owned())?),
    })
}

impl Serialize for BleOptions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut data = cbor!({
            0 => true, // peripheral_server_mode_supported
            1 => false, // central_client_mode_supported
            10 => ciborium::Value::Bytes(self.peripheral_server_uuid.into_bytes().to_vec())
        })
        .map_err(ser::Error::custom)?;

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

fn deserialize_ble_options<'de, D>(value: ciborium::Value) -> Result<BleOptions, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map = value
        .into_map()
        .map_err(|_| de::Error::custom("Invalid BleOptions"))?;

    let peripheral_server_mode_supported = get_cbor_map_value(&map, 0).ok_or(de::Error::custom(
        "Missing BleOptions peripheral_server_mode_supported",
    ))?;

    if !peripheral_server_mode_supported
        .as_bool()
        .is_some_and(|v| v)
    {
        return Err(de::Error::custom(
            "Invalid BleOptions peripheral_server_mode_supported",
        ));
    }

    let peripheral_server_uuid = get_cbor_map_value(&map, 10)
        .ok_or(de::Error::custom(
            "Missing BleOptions peripheral_server_uuid",
        ))?
        .to_owned()
        .into_bytes()
        .map_err(|_| de::Error::custom("Invalid BleOptions peripheral_server_uuid"))?;

    let peripheral_server_mac_address = if let Some(address) = get_cbor_map_value(&map, 20) {
        let bytes = address
            .to_owned()
            .into_bytes()
            .map_err(|_| de::Error::custom("Invalid BleOptions peripheral_server_mac_address"))?;
        Some(deserialize_mac_address(&bytes.try_into().map_err(
            |_| de::Error::custom("Invalid BleOptions peripheral_server_mac_address"),
        )?))
    } else {
        None
    };

    Ok(BleOptions {
        peripheral_server_uuid: Uuid::from_bytes(
            peripheral_server_uuid
                .try_into()
                .map_err(|_| de::Error::custom("Invalid BleOptions peripheral_server_uuid"))?,
        ),
        peripheral_server_mac_address,
    })
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
    use one_crypto::utilities::get_rng;
    use uuid::uuid;

    use super::*;

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

        let generated = engagement.clone().generate_qr_code().unwrap();
        let parsed = DeviceEngagement::parse_qr_code(&generated.qr_code_content).unwrap();

        assert_eq!(&engagement, parsed.inner());
        assert_eq!(generated.device_engagement, parsed);
        assert_eq!(
            generated.device_engagement.into_bytes(),
            parsed.into_bytes()
        );
    }

    #[test]
    fn test_device_engagement_deserialize_iso_example() {
        // ISO 18013-5, D.3.1
        let data = hex!(
            "a30063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d9\
             3e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32\
             fc670281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917"
        )
        .to_vec();

        // failing due to unsupported key type
        let failure = ciborium::from_reader::<DeviceEngagement, _>(&data[..]).unwrap_err();
        assert_eq!(
            failure.to_string(),
            "Semantic(None, \"Custom(\\\"Semantic(None, \\\\\\\"Unsupported key type, expected OKP(x25519) found Assigned(EC2)\\\\\\\")\\\")\")"
        );
    }

    fn get_example_engagement() -> DeviceEngagement {
        let pk = x25519_dalek::PublicKey::from(&x25519_dalek::EphemeralSecret::random_from_rng(
            get_rng(),
        ));

        DeviceEngagement {
            security: Security {
                key_bytes: EmbeddedCbor::new(EDeviceKey::new(pk)).unwrap(),
            },
            device_retrieval_methods: vec![DeviceRetrievalMethod {
                retrieval_options: RetrievalOptions::Ble(BleOptions {
                    peripheral_server_uuid: uuid!("18c39646-2c91-43d6-b0c7-8cc86efd2573"),
                    peripheral_server_mac_address: Some("F6:AC:82:54:69:B7".to_string()),
                }),
            }],
        }
    }
}
