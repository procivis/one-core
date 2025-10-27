use std::borrow::Cow;
use std::io::{Cursor, Read};

use ndef_rs::payload::RecordPayload;
use ndef_rs::{NdefMessage, NdefRecord, TNF};
use uuid::Uuid;

use super::ble_holder::ServerInfo;
use super::device_engagement::DeviceEngagement;
use crate::provider::credential_formatter::mdoc_formatter::util::EmbeddedCbor;

// ISO 18013-5 8.2.2.1
pub(super) const DEVICE_ENGAGMENT_RECORD_ID: &[u8] = b"mdoc";
pub(super) const DEVICE_ENGAGMENT_RECORD_TYPE: &[u8] = b"iso.org:18013:deviceengagement";

const BLE_CARRIER_DATA_REFERENCE: &[u8] = b"0"; // this is to be compatible with hardcoded choice in OWF implementation
pub(super) const BLE_RECORD_TYPE: &[u8] = b"application/vnd.bluetooth.le.oob";

const ALTERNATIVE_CARRIER_RECORD_TYPE: &[u8] = b"ac";
const HANDOVER_SELECT_RECORD_TYPE: &[u8] = b"Hs";

pub(crate) fn create_nfc_handover_select_message(
    server: &ServerInfo,
    device_engagement: EmbeddedCbor<DeviceEngagement>,
) -> Result<NdefMessage, ndef_rs::error::NdefError> {
    let alternative_carrier_record = AlternativeCarrierRecord {
        carrier_data_reference: BLE_CARRIER_DATA_REFERENCE.to_owned(),
        auxiliary_record_ids: vec![DEVICE_ENGAGMENT_RECORD_ID.to_owned()],
    };

    let mut alternative_carrier_message = NdefMessage::default();
    alternative_carrier_message.add_record(alternative_carrier_record.try_into()?);

    let mut nfc_message = NdefMessage::default();
    nfc_message.add_record(
        DeviceEngagementRecord {
            device_engagement: device_engagement.inner_bytes()?,
        }
        .try_into()?,
    );
    nfc_message.add_record(
        HandoverSelectRecord {
            version: 0x15,
            embedded_message: alternative_carrier_message.to_buffer()?,
        }
        .try_into()?,
    );
    nfc_message.add_record(
        BLECarrierConfigurationRecord {
            peripheral_service_uuid: server.service_uuid,
            peripheral_mac_address: if let Some(mac) = server.mac_address.as_ref() {
                Some(serialize_mac_address(mac)?)
            } else {
                None
            },
        }
        .try_into()?,
    );

    Ok(nfc_message)
}

pub(super) struct BLECarrierConfigurationRecord {
    pub(super) peripheral_service_uuid: Uuid,
    pub(super) peripheral_mac_address: Option<[u8; 6]>,
}

const BLE_CARRIER_ROLE: u8 = 0x1c;
const BLE_CARRIER_SERVICE_UUID: u8 = 0x07;
const BLE_CARRIER_MAC_ADDRESS: u8 = 0x1b;

impl RecordPayload for BLECarrierConfigurationRecord {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(BLE_RECORD_TYPE)
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        let mut buffer = Vec::new();
        buffer.push(0x02); // length
        buffer.push(BLE_CARRIER_ROLE); // LE Role
        buffer.push(0x00); // LE Role: mdocPeripheralServerMode

        let mut peripheral_service_uuid = self.peripheral_service_uuid.into_bytes();
        peripheral_service_uuid.reverse();
        buffer.push(peripheral_service_uuid.len() as u8 + 1);
        buffer.push(BLE_CARRIER_SERVICE_UUID);
        buffer.extend_from_slice(peripheral_service_uuid.as_slice());

        if let Some(peripheral_mac_address) = &self.peripheral_mac_address {
            let mut peripheral_mac_address = peripheral_mac_address.to_vec();
            peripheral_mac_address.reverse();
            buffer.push(peripheral_mac_address.len() as u8 + 1);
            buffer.push(BLE_CARRIER_MAC_ADDRESS);
            buffer.extend_from_slice(peripheral_mac_address.as_slice());
        }

        buffer.into()
    }
}

impl TryInto<NdefRecord> for BLECarrierConfigurationRecord {
    type Error = ndef_rs::error::NdefError;

    fn try_into(self) -> Result<NdefRecord, Self::Error> {
        NdefRecord::builder()
            .tnf(TNF::MimeMedia)
            .id(BLE_CARRIER_DATA_REFERENCE.to_vec())
            .payload(&self)
            .build()
    }
}

impl TryFrom<&NdefRecord> for BLECarrierConfigurationRecord {
    type Error = ndef_rs::error::NdefError;

    fn try_from(record: &NdefRecord) -> Result<Self, Self::Error> {
        if record.tnf() != TNF::MimeMedia {
            return Err(Self::Error::InvalidTnf);
        }
        if record.record_type() != BLE_RECORD_TYPE {
            return Err(Self::Error::InvalidRecordType);
        }

        let entries = read_record_entries(&mut Cursor::new(record.payload()))?;

        let role = &entries
            .iter()
            .find(|entry| entry.r#type == BLE_CARRIER_ROLE)
            .ok_or(Self::Error::InvalidPayload)?
            .content;
        if role.as_slice() != [0x00] {
            return Err(anyhow::anyhow!("Unsupported BLE role {role:?}").into());
        }

        let mut service_uuid = entries
            .iter()
            .find(|entry| entry.r#type == BLE_CARRIER_SERVICE_UUID)
            .ok_or(Self::Error::InvalidPayload)?
            .content
            .to_owned();
        service_uuid.reverse();

        let mac_address = if let Some(entry) = entries
            .iter()
            .find(|entry| entry.r#type == BLE_CARRIER_MAC_ADDRESS)
        {
            let mut address = entry.content.to_owned();
            address.reverse();
            Some(
                address
                    .try_into()
                    .map_err(|_| ndef_rs::error::NdefError::InvalidPayload)?,
            )
        } else {
            None
        };

        Ok(Self {
            peripheral_service_uuid: Uuid::from_bytes(
                service_uuid
                    .try_into()
                    .map_err(|v| anyhow::anyhow!("Invalid service uuid: {v:?}"))?,
            ),
            peripheral_mac_address: mac_address,
        })
    }
}

pub(super) struct AlternativeCarrierRecord {
    pub(super) carrier_data_reference: Vec<u8>,
    pub(super) auxiliary_record_ids: Vec<Vec<u8>>,
}

impl RecordPayload for AlternativeCarrierRecord {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(ALTERNATIVE_CARRIER_RECORD_TYPE)
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        let mut buffer = Vec::new();
        buffer.push(0x01);
        buffer.push(self.carrier_data_reference.len() as u8);
        buffer.extend_from_slice(self.carrier_data_reference.as_slice());
        buffer.push(self.auxiliary_record_ids.len() as u8);
        for auxiliary_record_id in &self.auxiliary_record_ids {
            buffer.push(auxiliary_record_id.len() as u8);
            buffer.extend_from_slice(auxiliary_record_id.as_slice());
        }
        buffer.into()
    }
}

impl TryInto<NdefRecord> for AlternativeCarrierRecord {
    type Error = ndef_rs::error::NdefError;

    fn try_into(self) -> Result<NdefRecord, Self::Error> {
        NdefRecord::builder()
            .tnf(TNF::WellKnown)
            .payload(&self)
            .build()
    }
}

pub(super) struct HandoverSelectRecord {
    pub(super) version: u8,
    pub(super) embedded_message: Vec<u8>,
}

impl RecordPayload for HandoverSelectRecord {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(HANDOVER_SELECT_RECORD_TYPE)
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        let mut bytes = Vec::new();
        bytes.push(self.version);
        bytes.append(&mut self.embedded_message.clone());
        bytes.into()
    }
}

impl TryInto<NdefRecord> for HandoverSelectRecord {
    type Error = ndef_rs::error::NdefError;

    fn try_into(self) -> Result<NdefRecord, Self::Error> {
        NdefRecord::builder()
            .tnf(TNF::WellKnown)
            .payload(&self)
            .build()
    }
}

pub(super) struct DeviceEngagementRecord {
    pub(super) device_engagement: Vec<u8>,
}

impl RecordPayload for DeviceEngagementRecord {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(DEVICE_ENGAGMENT_RECORD_TYPE)
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        self.device_engagement.clone().into()
    }
}

impl TryInto<NdefRecord> for DeviceEngagementRecord {
    type Error = ndef_rs::error::NdefError;

    fn try_into(self) -> Result<NdefRecord, Self::Error> {
        NdefRecord::builder()
            .tnf(TNF::External)
            .id(DEVICE_ENGAGMENT_RECORD_ID.to_vec())
            .payload(&self)
            .build()
    }
}

struct Entry {
    pub r#type: u8,
    pub content: Vec<u8>,
}

fn read_record_entries(r: &mut Cursor<&[u8]>) -> Result<Vec<Entry>, ndef_rs::error::NdefError> {
    let mut result = vec![];
    while let Some(entry) = read_record_entry(r)? {
        result.push(entry);
    }
    Ok(result)
}

fn read_record_entry(r: &mut Cursor<&[u8]>) -> Result<Option<Entry>, ndef_rs::error::NdefError> {
    let mut length = [0; 1];
    if r.read_exact(&mut length).is_err() {
        return Ok(None);
    }
    let length = length[0];
    if length == 0 {
        return Err(ndef_rs::error::NdefError::InvalidEncoding);
    }

    let mut data: Vec<u8> = vec![0; length as _];
    r.read_exact(data.as_mut_slice())
        .map_err(|_| ndef_rs::error::NdefError::InvalidEncoding)?;

    Ok(Some(Entry {
        r#type: data.remove(0),
        content: data,
    }))
}

fn serialize_mac_address(mac: &str) -> Result<[u8; 6], ndef_rs::error::NdefError> {
    mac.split(':')
        .map(|part| u8::from_str_radix(part, 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| ndef_rs::error::NdefError::InvalidEncoding)?
        .try_into()
        .map_err(|_| ndef_rs::error::NdefError::InvalidEncoding)
}
