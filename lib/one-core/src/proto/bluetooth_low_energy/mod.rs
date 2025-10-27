use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) mod ble_resource;
pub mod low_level;

#[derive(Debug, Error, Serialize, Deserialize, Clone)]
pub enum BleError {
    #[error("BLE adapter not enabled")]
    AdapterNotEnabled,
    #[error("BLE scan already started")]
    ScanAlreadyStarted,
    #[error("BLE scan not started")]
    ScanNotStarted,
    #[error("Advertisement already started")]
    BroadcastAlreadyStarted,
    #[error("Advertisement not started")]
    BroadcastNotStarted,
    #[error("Another write or read operation is in progress")]
    AnotherOperationInProgress,
    #[error("Data too long")]
    WriteDataTooLong,
    #[error("No device with address {address} found")]
    DeviceAddressNotFound { address: String },
    #[error("Service with UUID {service} not found")]
    ServiceNotFound { service: String },
    #[error("Characteristic with UUID {characteristic} not found")]
    CharacteristicNotFound { characteristic: String },
    #[error("Invalid UUID: {uuid}")]
    InvalidUUID { uuid: String },
    #[error("Not connected to device {address}")]
    DeviceNotConnected { address: String },
    #[error(
        "Operation {operation} can not be performed on characteristic {characteristic}, service UUID {service}"
    )]
    InvalidCharacteristicOperation {
        service: String,
        characteristic: String,
        operation: String,
    },
    #[error("The device does not support BLE")]
    NotSupported,
    #[error("Application not authorized to use BLE")]
    NotAuthorized,
    #[error("GATT server not running")]
    ServerNotRunning,
    #[error("Unknown BLE error: {reason}")]
    Unknown { reason: String },
}
