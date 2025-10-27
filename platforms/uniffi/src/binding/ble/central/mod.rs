use std::collections::HashMap;
use std::sync::Arc;

use one_core::proto::bluetooth_low_energy::low_level::dto::{
    CharacteristicUUID, CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
    ServiceUUID,
};
use one_dto_mapper::{From, Into};

use crate::error::BleError;

mod imp;

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait BleCentral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, crate::error::BleError>;
    async fn start_scan(
        &self,
        filter_services: Option<Vec<ServiceUUID>>,
    ) -> Result<(), crate::error::BleError>;
    async fn stop_scan(&self) -> Result<(), crate::error::BleError>;
    async fn is_scanning(&self) -> Result<bool, crate::error::BleError>;
    async fn write_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: Vec<u8>,
        write_type: CharacteristicWriteTypeBindingEnum,
    ) -> Result<(), crate::error::BleError>;
    async fn read_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<u8>, crate::error::BleError>;
    async fn connect(&self, peripheral: DeviceAddress) -> Result<u16, crate::error::BleError>;
    async fn disconnect(&self, peripheral: DeviceAddress) -> Result<(), crate::error::BleError>;
    async fn get_discovered_devices(
        &self,
    ) -> Result<Vec<PeripheralDiscoveryDataBindingDTO>, BleError>;
    async fn subscribe_to_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), crate::error::BleError>;
    async fn unsubscribe_from_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), crate::error::BleError>;
    async fn get_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, crate::error::BleError>;
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(CharacteristicWriteType)]
pub enum CharacteristicWriteTypeBindingEnum {
    WithResponse,
    WithoutResponse,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(PeripheralDiscoveryData)]
pub struct PeripheralDiscoveryDataBindingDTO {
    pub device_address: DeviceAddress,
    pub local_device_name: Option<String>,
    pub advertised_services: Vec<ServiceUUID>,
    pub advertised_service_data: Option<HashMap<ServiceUUID, Vec<u8>>>,
}

pub struct BleCentralWrapper(pub Arc<dyn BleCentral>);
