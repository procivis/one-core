use std::collections::HashMap;

use thiserror::Error;

pub mod ble_central;
pub mod ble_peripheral;

pub type MacAddress = String;
pub type ServiceUUID = String;
pub type CharacteristicUUID = String;
pub type DeviceAddress = String;

#[derive(Debug, Error)]
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
    #[error("Operation {operation} can not be performed on characteristic {characteristic}, service UUID {service}")]
    InvalidCharacteristicOperation {
        service: String,
        characteristic: String,
        operation: String,
    },
    #[error("The device does not support BLE")]
    NotSupported,
    #[error("Application not authorized to use BLE")]
    NotAuthorized,
    #[error("Unknown BLE error: {reason}")]
    Unknown { reason: String },
}

pub enum ConnectionEvent {
    Connected { device_info: DeviceInfo },
    Disconnected { device_address: DeviceAddress },
}

pub enum CharacteristicPermissions {
    Read,
    Write,
}

pub enum CharacteristicProperties {
    Read,
    Write,
    Notify,
    WriteWithoutResponse,
    Indicate,
}

pub enum CharacteristicWriteType {
    WithResponse,
    WithoutResponse,
}

pub struct DeviceInfo {
    pub address: DeviceAddress,
    pub mtu: u16,
}

pub struct ServiceDescription {
    pub uuid: ServiceUUID,
    pub advertise: bool,
    pub advertised_service_data: Option<Vec<u8>>,
    pub characteristics: Vec<CreateCharacteristicOptions>,
}

pub struct CreateCharacteristicOptions {
    pub uuid: CharacteristicUUID,
    pub permissions: Vec<CharacteristicPermissions>,
    pub properties: Vec<CharacteristicProperties>,
    pub initial_value: Option<Vec<u8>>,
}

pub struct PeripheralDiscoveryData {
    pub device_address: DeviceAddress,
    pub local_device_name: Option<String>,
    pub advertised_services: Vec<ServiceUUID>,
    pub advertised_service_data: Option<HashMap<ServiceUUID, Vec<u8>>>,
}
