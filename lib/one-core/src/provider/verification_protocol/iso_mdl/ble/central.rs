//! Common functionality on central (client) side
//! holder during central-client mode, verifier during peripheral-server mode

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::common::PeerInfo;
use super::{Chunk, Command, split_into_chunks};
use crate::error::ContextWithErrorCode;
use crate::proto::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::proto::bluetooth_low_energy::low_level::dto::{
    CharacteristicWriteType, PeripheralDiscoveryData,
};
use crate::provider::verification_protocol::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::to_cbor;

pub(super) async fn read_chunked<T: DeserializeOwned>(
    central: &impl BleCentral,
    connection: &PeerInfo,
    server_2_client_characteristic: &str,
) -> Result<T, VerificationProtocolError> {
    let mut result = vec![];

    loop {
        let data = central
            .get_notifications(
                connection.address.clone(),
                connection.service_uuid.to_string(),
                server_2_client_characteristic.into(),
            )
            .await
            .error_while("waiting for Server2Client notification")?;

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
    central: &impl BleCentral,
    connection: &PeerInfo,
    client_2_server_characteristic: &str,
) -> Result<(), VerificationProtocolError> {
    let message = to_cbor(message)?;

    for chunk in split_into_chunks(message, connection.mtu)? {
        central
            .write_data(
                connection.address.to_owned(),
                connection.service_uuid.to_string(),
                client_2_server_characteristic.into(),
                &chunk,
                CharacteristicWriteType::WithoutResponse,
            )
            .await
            .error_while("writing Client2Server data")?;
    }

    Ok(())
}

pub(super) async fn send_end_command(
    central: &impl BleCentral,
    connection: &PeerInfo,
    state_characteristic: &str,
) {
    if let Err(err) = central
        .write_data(
            connection.address.to_owned(),
            connection.service_uuid.to_string(),
            state_characteristic.into(),
            &[Command::End as _],
            CharacteristicWriteType::WithoutResponse,
        )
        .await
    {
        tracing::warn!(%err, "failed to write End command");
    }
}

pub(super) async fn wait_for_connection(
    central: &impl BleCentral,
    service_uuid: &Uuid,
    server_2_client_characteristic: &str,
    state_characteristic: &str,
) -> Result<(PeripheralDiscoveryData, usize), VerificationProtocolError> {
    let device = central
        .get_discovered_devices()
        .await
        .error_while("getting discovered devices")?
        .pop()
        .ok_or(VerificationProtocolError::Failed(
            "no discovered devices".to_string(),
        ))?;

    central.stop_scan().await.error_while("stopping BLE scan")?;

    let mtu_size = central
        .connect(device.device_address.clone())
        .await
        .error_while("connecting to peripheral")?;

    central
        .subscribe_to_characteristic_notifications(
            device.device_address.clone(),
            service_uuid.to_string(),
            state_characteristic.into(),
        )
        .await
        .error_while("subscribing State characteristic")?;

    central
        .subscribe_to_characteristic_notifications(
            device.device_address.clone(),
            service_uuid.to_string(),
            server_2_client_characteristic.into(),
        )
        .await
        .error_while("subscribing Server2Client characteristic")?;

    central
        .write_data(
            device.device_address.clone(),
            service_uuid.to_string(),
            state_characteristic.into(),
            &[Command::Start as _],
            CharacteristicWriteType::WithoutResponse,
        )
        .await
        .error_while("writing Start command")?;

    Ok((device, mtu_size as _))
}
