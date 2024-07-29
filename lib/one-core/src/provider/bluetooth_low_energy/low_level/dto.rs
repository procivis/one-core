use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub type MacAddress = String;
pub type ServiceUUID = String;
pub type CharacteristicUUID = String;
pub type DeviceAddress = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionEvent {
    Connected { device_info: DeviceInfo },
    Disconnected { device_address: DeviceAddress },
}

#[derive(Debug, Clone)]
pub enum CharacteristicPermissions {
    Read,
    Write,
}

#[derive(Debug, Clone)]
pub enum CharacteristicProperties {
    Read,
    Write,
    Notify,
    WriteWithoutResponse,
    Indicate,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CharacteristicWriteType {
    WithResponse,
    WithoutResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub address: DeviceAddress,
    mtu: u16,
}

impl DeviceInfo {
    pub fn new(address: DeviceAddress, mtu: u16) -> Self {
        Self { address, mtu }
    }

    pub fn mtu(&self) -> u16 {
        // we need to send data bellow the agreed MTU since on some devices the header overhead is part of the negotiated MTU
        const HEADER_OVERHEAD: u16 = 3;

        self.mtu - HEADER_OVERHEAD
    }
}

#[derive(Debug, Clone)]
pub struct ServiceDescription {
    pub uuid: ServiceUUID,
    pub advertise: bool,
    pub advertised_service_data: Option<Vec<u8>>,
    pub characteristics: Vec<CreateCharacteristicOptions>,
}

#[derive(Debug, Clone)]
pub struct CreateCharacteristicOptions {
    pub uuid: CharacteristicUUID,
    pub permissions: Vec<CharacteristicPermissions>,
    pub properties: Vec<CharacteristicProperties>,
    pub initial_value: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PeripheralDiscoveryData {
    pub device_address: DeviceAddress,
    pub local_device_name: Option<String>,
    pub advertised_services: Vec<ServiceUUID>,
    pub advertised_service_data: Option<HashMap<ServiceUUID, Vec<u8>>>,
}
