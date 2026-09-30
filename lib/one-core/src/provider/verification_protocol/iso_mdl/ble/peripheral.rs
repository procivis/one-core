//! Common functionality on peripheral side
//! holder during peripheral-server mode, verifier during central-client mode

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::{Chunk, Command, split_into_chunks};
use crate::error::ContextWithErrorCode;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::{
    ConnectionEvent, DeviceAddress, DeviceInfo,
};
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::common::to_cbor;

pub(super) async fn read_chunked<T: DeserializeOwned>(
    peripheral: &impl BlePeripheral,
    device_address: &DeviceAddress,
    service_uuid: &Uuid,
    client_2_server_characteristic: &str,
) -> Result<T, VerificationProtocolError> {
    let mut result = vec![];

    loop {
        let data = peripheral
            .get_characteristic_writes(
                device_address.clone(),
                service_uuid.to_string(),
                client_2_server_characteristic.into(),
            )
            .await
            .error_while("waiting for Client2Server characteristic write")?;

        for msg in data {
            let chunk: Chunk = msg.try_into()?;
            match chunk {
                Chunk::Next(payload) => result.extend(payload),
                Chunk::Last(payload) => {
                    result.extend(payload);

                    return Ok(ciborium::from_reader(result.as_slice())?);
                }
            }
        }
    }
}

pub(super) async fn write_chunked<T: Serialize>(
    message: &T,
    peripheral: &impl BlePeripheral,
    device_address: &DeviceAddress,
    service_uuid: &Uuid,
    server_2_client_characteristic: &str,
    mtu_size: usize,
) -> Result<(), VerificationProtocolError> {
    let message = to_cbor(message)?;

    for chunk in split_into_chunks(message, mtu_size)? {
        peripheral
            .notify_characteristic_data(
                device_address.to_owned(),
                service_uuid.to_string(),
                server_2_client_characteristic.into(),
                &chunk,
            )
            .await
            .error_while("notifying Server2Client data")?;
    }

    Ok(())
}

pub(super) async fn wait_for_active_device(
    peripheral: &impl BlePeripheral,
    service_uuid: &Uuid,
    state_characteristic: &str,
) -> Result<DeviceInfo, VerificationProtocolError> {
    loop {
        let connected_devices = peripheral
            .get_connection_change_events()
            .await
            .error_while("waiting for BLE connection event")?
            .into_iter()
            .filter_map(|info| match info {
                ConnectionEvent::Connected { device_info } => Some(device_info),
                ConnectionEvent::Disconnected { .. } => None,
            });

        for connected_device in connected_devices {
            tracing::debug!("device connected: {connected_device:?}");

            if wait_for_start_command(
                peripheral,
                &connected_device,
                service_uuid,
                state_characteristic,
            )
            .await?
            {
                peripheral
                    .stop_advertisement()
                    .await
                    .error_while("stopping BLE advertisement")?;

                return Ok(connected_device);
            }
        }
    }
}

/// Wait for Start command according to ISO 18013-5 (8.3.3.1.1.6 Data retrieval)
///
/// - returns `true` if Start command was written
/// - returns `false` if no command was written and reconnection should happen
async fn wait_for_start_command(
    peripheral: &impl BlePeripheral,
    info: &DeviceInfo,
    service_uuid: &Uuid,
    state_characteristic: &str,
) -> Result<bool, VerificationProtocolError> {
    let command_written = match peripheral
        .get_characteristic_writes(
            info.address.clone(),
            service_uuid.to_string(),
            state_characteristic.into(),
        )
        .await
    {
        Ok(writes) => writes.concat(),
        Err(err) => {
            tracing::warn!(%err, "Failed to receive State command");
            // according to ISO 18013-5 (8.3.3.1.1.8 Connection re-establishment),
            // re-connection in this phase is allowed
            return Ok(false);
        }
    };

    let command: Command = command_written.try_into()?;
    match command {
        Command::Start => Ok(true),
        command => Err(VerificationProtocolError::Failed(format!(
            "invalid State command: {}",
            command as u8
        ))),
    }
}

pub(super) async fn notify_end(
    peripheral: &impl BlePeripheral,
    device_address: &DeviceAddress,
    service_uuid: &Uuid,
    state_characteristic: &str,
) {
    let result = peripheral
        .notify_characteristic_data(
            device_address.clone(),
            service_uuid.to_string(),
            state_characteristic.into(),
            &[Command::End as _],
        )
        .await;
    if let Err(err) = result {
        tracing::warn!(%err, "Failed to notify State command End");
    }
}
