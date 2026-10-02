//! Common functionality on both sides holder/verifier as well as both BLE modes

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{central, central_client_mode, peripheral, peripheral_server_mode};
use crate::model::proof::ProofRole;
use crate::proto::bluetooth_low_energy::low_level::ble_central::BleCentral;
use crate::proto::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral;
use crate::proto::bluetooth_low_energy::low_level::dto::DeviceAddress;
use crate::provider::verification_protocol::error::VerificationProtocolError;

/// Connection details about a BLE peer together with used BLE mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum ConnectedPeer {
    /// mdoc central client mode, ISO 18013-5, 8.3.3.1.1
    CentralClientMode(PeerInfo),
    /// mdoc peripheral server mode, ISO 18013-5, 8.3.3.1.1
    PeripheralServerMode(PeerInfo),
}

/// Details about a BLE peer connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PeerInfo {
    pub address: DeviceAddress,
    /// derived from the negotiated MTU, lowered by MTU_HEADER_OVERHEAD
    pub max_payload_size: usize,
    pub service_uuid: Uuid,
}

pub(super) async fn read_session_message<T: DeserializeOwned>(
    caller_role: ProofRole,
    central: &impl BleCentral,
    peripheral: &impl BlePeripheral,
    peer: &ConnectedPeer,
) -> Result<T, VerificationProtocolError> {
    match (caller_role, peer) {
        (ProofRole::Holder, ConnectedPeer::CentralClientMode(connection))
        | (ProofRole::Verifier, ConnectedPeer::PeripheralServerMode(connection)) => {
            central::read_chunked(central, connection, server_2_client_characteristic(peer)).await
        }
        (ProofRole::Holder, ConnectedPeer::PeripheralServerMode(connection))
        | (ProofRole::Verifier, ConnectedPeer::CentralClientMode(connection)) => {
            peripheral::read_chunked(peripheral, connection, client_2_server_characteristic(peer))
                .await
        }
    }
}

pub(super) async fn send_session_message<T: Serialize>(
    sender_role: ProofRole,
    central: &impl BleCentral,
    peripheral: &impl BlePeripheral,
    message: &T,
    peer: &ConnectedPeer,
    should_disconnect_after: bool,
) -> Result<(), VerificationProtocolError> {
    match (sender_role, peer) {
        (ProofRole::Holder, ConnectedPeer::CentralClientMode(connection))
        | (ProofRole::Verifier, ConnectedPeer::PeripheralServerMode(connection)) => {
            central::write_chunked(
                message,
                central,
                connection,
                client_2_server_characteristic(peer),
            )
            .await?;

            if should_disconnect_after
                && let Err(err) = central.disconnect(connection.address.to_owned()).await
            {
                tracing::warn!("failed to disconnect BLE central: {err}");
            }
        }
        (ProofRole::Holder, ConnectedPeer::PeripheralServerMode(connection))
        | (ProofRole::Verifier, ConnectedPeer::CentralClientMode(connection)) => {
            peripheral::write_chunked(
                message,
                peripheral,
                connection,
                server_2_client_characteristic(peer),
            )
            .await?;

            if should_disconnect_after {
                // Wait for client disconnection here (but this means blocking UI)
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };

    Ok(())
}

pub(super) async fn send_end(
    sender_role: ProofRole,
    central: &impl BleCentral,
    peripheral: &impl BlePeripheral,
    peer: Option<&ConnectedPeer>,
) {
    let Some(peer) = peer else {
        return;
    };

    match (sender_role, peer) {
        (ProofRole::Holder, ConnectedPeer::CentralClientMode(connection))
        | (ProofRole::Verifier, ConnectedPeer::PeripheralServerMode(connection)) => {
            central::send_end_command(central, connection, state_characteristic(peer)).await
        }
        (ProofRole::Holder, ConnectedPeer::PeripheralServerMode(connection))
        | (ProofRole::Verifier, ConnectedPeer::CentralClientMode(connection)) => {
            peripheral::notify_end(peripheral, connection, state_characteristic(peer)).await
        }
    }
}

fn server_2_client_characteristic(for_connection: &ConnectedPeer) -> &str {
    match for_connection {
        ConnectedPeer::CentralClientMode(_) => central_client_mode::SERVER_2_CLIENT,
        ConnectedPeer::PeripheralServerMode(_) => peripheral_server_mode::SERVER_2_CLIENT,
    }
}

fn client_2_server_characteristic(for_connection: &ConnectedPeer) -> &str {
    match for_connection {
        ConnectedPeer::CentralClientMode(_) => central_client_mode::CLIENT_2_SERVER,
        ConnectedPeer::PeripheralServerMode(_) => peripheral_server_mode::CLIENT_2_SERVER,
    }
}

fn state_characteristic(for_connection: &ConnectedPeer) -> &str {
    match for_connection {
        ConnectedPeer::CentralClientMode(_) => central_client_mode::STATE,
        ConnectedPeer::PeripheralServerMode(_) => peripheral_server_mode::STATE,
    }
}
