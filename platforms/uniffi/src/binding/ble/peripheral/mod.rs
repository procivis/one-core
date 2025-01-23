use std::sync::Arc;

use one_core::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicPermissions, CharacteristicProperties, CharacteristicUUID, ConnectionEvent,
    CreateCharacteristicOptions, DeviceAddress, MacAddress, ServiceDescription, ServiceUUID,
};
use one_dto_mapper::{convert_inner, From, Into};

use crate::error::BleError;

mod imp;

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BlePeripheral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError>;
    async fn start_advertisement(
        &self,
        device_name: Option<String>,
        services: Vec<ServiceDescriptionBindingDTO>,
    ) -> Result<Option<MacAddress>, BleError>;
    async fn stop_advertisement(&self) -> Result<(), BleError>;
    async fn is_advertising(&self) -> Result<bool, BleError>;
    async fn set_characteristic_data(
        &self,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
    ) -> Result<(), BleError>;
    async fn notify_characteristic_data(
        &self,
        device_address: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
    ) -> Result<(), BleError>;
    async fn get_connection_change_events(
        &self,
    ) -> Result<Vec<ConnectionEventBindingEnum>, BleError>;
    async fn get_characteristic_writes(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError>;
    async fn wait_for_characteristic_read(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError>;
    async fn stop_server(&self) -> Result<(), BleError>;
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ServiceDescription)]
pub struct ServiceDescriptionBindingDTO {
    pub uuid: String,
    pub advertise: bool,
    pub advertised_service_data: Option<Vec<u8>>,
    #[from(with_fn = convert_inner)]
    pub characteristics: Vec<CharacteristicBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CreateCharacteristicOptions)]
pub struct CharacteristicBindingDTO {
    pub uuid: String,
    #[from(with_fn = convert_inner)]
    pub permissions: Vec<CharacteristicPermissionBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub properties: Vec<CharacteristicPropertyBindingEnum>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(CharacteristicPermissions)]
pub enum CharacteristicPermissionBindingEnum {
    Read,
    Write,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(CharacteristicProperties)]
pub enum CharacteristicPropertyBindingEnum {
    Read,
    Write,
    Notify,
    WriteWithoutResponse,
    Indicate,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ConnectionEvent)]
pub enum ConnectionEventBindingEnum {
    Connected { device_info: DeviceInfoBindingDTO },
    Disconnected { device_address: DeviceAddress },
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct DeviceInfoBindingDTO {
    pub address: String,
    pub mtu: u16,
}

pub struct BlePeripheralWrapper(pub Arc<dyn BlePeripheral>);
