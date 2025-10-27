use super::dto::{
    CharacteristicUUID, ConnectionEvent, DeviceAddress, MacAddress, ServiceDescription, ServiceUUID,
};
use crate::proto::bluetooth_low_energy::BleError;

mod tracking_wrapper;
pub use tracking_wrapper::TrackingBlePeripheral;

#[cfg_attr(test, mockall::automock)]
#[async_trait::async_trait]
pub trait BlePeripheral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError>;
    async fn start_advertisement(
        &self,
        device_name: Option<String>,
        services: Vec<ServiceDescription>,
    ) -> Result<Option<MacAddress>, BleError>;
    async fn stop_advertisement(&self) -> Result<(), BleError>;
    async fn is_advertising(&self) -> Result<bool, BleError>;
    async fn set_characteristic_data(
        &self,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
    ) -> Result<(), BleError>;
    async fn notify_characteristic_data(
        &self,
        device_address: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
    ) -> Result<(), BleError>;
    async fn get_connection_change_events(&self) -> Result<Vec<ConnectionEvent>, BleError>;
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
