use std::borrow::Cow;

use ndef_rs::payload::RecordPayload;
use ndef_rs::{NdefMessage, NdefRecord, TNF};
use uuid::Uuid;

use crate::provider::verification_protocol::iso_mdl::ble_holder::ServerInfo;
use crate::provider::verification_protocol::iso_mdl::device_engagement::DeviceEngagement;
use crate::util::mdoc::EmbeddedCbor;

pub(super) const MDOC_AUXILIARY_DATA_RECORD_ID: &str = "mdoc";
pub(super) const BLE_CARRIER_DATA_REFERENCE: &str = "BLE";

pub(super) fn create_nfc_payload(
    server: ServerInfo,
    device_engagement: EmbeddedCbor<DeviceEngagement>,
) -> Result<NdefMessage, ndef_rs::error::NdefError> {
    let alternative_carrier_record = AlternativeCarrierRecord {
        carrier_data_reference: BLE_CARRIER_DATA_REFERENCE.to_owned(),
        auxiliary_record_ids: vec![MDOC_AUXILIARY_DATA_RECORD_ID.to_owned()],
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
            peripheral_service_uuid: Some(server.service_uuid),
            peripheral_mac_address: server.mac_address,
        }
        .try_into()?,
    );

    Ok(nfc_message)
}

pub(super) struct BLECarrierConfigurationRecord {
    pub(super) peripheral_service_uuid: Option<Uuid>,
    pub(super) peripheral_mac_address: Option<String>,
}

impl RecordPayload for BLECarrierConfigurationRecord {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(b"application/vnd.bluetooth.le.oob")
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        let mut buffer = Vec::new();
        buffer.push(0x02); // length
        buffer.push(0x1c); // LE Role
        buffer.push(0x00); // LE Role: mdocPeripheralServerMode
        if let Some(peripheral_service_uuid) = &self.peripheral_service_uuid {
            let mut peripheral_service_uuid = peripheral_service_uuid.into_bytes();
            peripheral_service_uuid.reverse();

            buffer.push(peripheral_service_uuid.len() as u8 + 1);
            buffer.push(0x07); // Service UUID
            buffer.extend_from_slice(peripheral_service_uuid.as_slice());
        }

        if let Some(peripheral_mac_address) = &self.peripheral_mac_address {
            let mut peripheral_mac_address = peripheral_mac_address.clone().into_bytes();
            peripheral_mac_address.reverse();
            buffer.push(peripheral_mac_address.len() as u8 + 1);
            buffer.push(0x1b); // Device Address
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
            .id(BLE_CARRIER_DATA_REFERENCE.to_owned().into_bytes())
            .payload(&self)
            .build()
    }
}

pub(super) struct AlternativeCarrierRecord {
    pub(super) carrier_data_reference: String,
    pub(super) auxiliary_record_ids: Vec<String>,
}

impl RecordPayload for AlternativeCarrierRecord {
    fn record_type(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(b"ac")
    }

    fn payload(&self) -> Cow<'_, [u8]> {
        let mut buffer = Vec::new();
        buffer.push(0x01);
        buffer.push(self.carrier_data_reference.len() as u8);
        buffer.extend_from_slice(self.carrier_data_reference.as_bytes());
        buffer.push(self.auxiliary_record_ids.len() as u8);
        for auxiliary_record_id in &self.auxiliary_record_ids {
            buffer.push(auxiliary_record_id.len() as u8);
            buffer.extend_from_slice(auxiliary_record_id.as_bytes());
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
        Cow::Borrowed(b"Hs")
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
        Cow::Borrowed(b"iso.org:18013:deviceengagement")
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
            .id(MDOC_AUXILIARY_DATA_RECORD_ID.to_owned().into_bytes())
            .payload(&self)
            .build()
    }
}
