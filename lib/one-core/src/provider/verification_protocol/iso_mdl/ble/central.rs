//! Common functionality on central (client) side
//! holder during central-client mode, verifier during peripheral-server mode

use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use super::common::PeerInfo;
use super::{Chunk, Command, split_into_chunks};
use crate::error::ContextWithErrorCode;
use crate::proto::bluetooth_low_energy::BleError;
use crate::proto::bluetooth_low_energy::low_level::MTU_HEADER_OVERHEAD;
use crate::proto::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::proto::bluetooth_low_energy::low_level::dto::CharacteristicWriteType;
use crate::provider::verification_protocol::VerificationProtocolError;
use crate::provider::verification_protocol::iso_mdl::to_cbor;

pub(super) async fn read_chunked<T: DeserializeOwned>(
    central: &impl BleCentral,
    connection: &PeerInfo,
    server_2_client_characteristic: &str,
) -> Result<T, VerificationProtocolError> {
    tracing::debug!("Awaiting message, characteristic: {server_2_client_characteristic}");

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
            tracing::trace!(
                "Received chunk ({chunk:?}), characteristic: {server_2_client_characteristic}"
            );

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
    tracing::debug!("Writing message, characteristic: {client_2_server_characteristic}");

    let message = to_cbor(message)?;

    for chunk in split_into_chunks(message, connection.max_payload_size)? {
        tracing::trace!(
            "Writing chunk, length: {}, characteristic: {client_2_server_characteristic}",
            chunk.len()
        );
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
    tracing::debug!("Writing End command: {state_characteristic}");

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
) -> Result<PeerInfo, VerificationProtocolError> {
    tracing::debug!("Awaiting connections: {state_characteristic}");

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

    let max_payload_size = mtu_size - MTU_HEADER_OVERHEAD;
    Ok(PeerInfo {
        address: device.device_address,
        max_payload_size: max_payload_size as _,
        service_uuid: *service_uuid,
    })
}

pub(super) async fn wait_for_end_command(
    central: &impl BleCentral,
    connection: &PeerInfo,
    state_characteristic: &str,
    timeout: Duration,
) {
    tracing::debug!("Awaiting End command: {state_characteristic}");

    let end_received = async {
        loop {
            let notifications = central
                .get_notifications(
                    connection.address.to_owned(),
                    connection.service_uuid.to_string(),
                    state_characteristic.into(),
                )
                .await?;

            if notifications
                .into_iter()
                .any(|notification| matches!(Command::try_from(notification), Ok(Command::End)))
            {
                return Ok::<_, BleError>(());
            }
        }
    };

    match tokio::time::timeout(timeout, end_received).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::info!(%err, "Failed to receive End command"),
        Err(_) => tracing::info!("Timeout waiting for End command"),
    }
}
