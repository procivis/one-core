use std::sync::Arc;

use dto_mapper::convert_inner_of_inner;
use one_core::provider::bluetooth_low_energy::low_level::dto::{
    CharacteristicUUID, ConnectionEvent, DeviceAddress, MacAddress, ServiceDescription, ServiceUUID,
};
use one_core::provider::bluetooth_low_energy::BleError;

pub struct BlePeripheralWrapper(pub Arc<dyn crate::BlePeripheral>);

#[async_trait::async_trait]
impl one_core::provider::bluetooth_low_energy::low_level::ble_peripheral::BlePeripheral
    for BlePeripheralWrapper
{
    async fn is_adapter_enabled(&self) -> Result<bool, BleError> {
        self.0.is_adapter_enabled().await.map_err(BleError::from)
    }

    async fn start_advertisement(
        &self,
        device_name: Option<String>,
        services: Vec<ServiceDescription>,
    ) -> Result<Option<MacAddress>, BleError> {
        let services = services.into_iter().map(|s| s.into()).collect();

        self.0
            .start_advertisement(device_name, services)
            .await
            .map_err(BleError::from)
    }

    async fn stop_advertisement(&self) -> Result<(), BleError> {
        self.0.stop_advertisement().await.map_err(BleError::from)
    }

    async fn is_advertising(&self) -> Result<bool, BleError> {
        self.0.is_advertising().await.map_err(BleError::from)
    }

    async fn set_characteristic_data(
        &self,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
    ) -> Result<(), BleError> {
        self.0
            .set_characteristic_data(service, characteristic, data.to_owned())
            .await
            .map_err(BleError::from)
    }

    async fn notify_characteristic_data(
        &self,
        device_address: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
    ) -> Result<(), BleError> {
        self.0
            .notify_characteristic_data(device_address, service, characteristic, data.to_owned())
            .await
            .map_err(BleError::from)
    }

    async fn get_connection_change_events(&self) -> Result<Vec<ConnectionEvent>, BleError> {
        convert_inner_of_inner(
            self.0
                .get_connection_change_events()
                .await
                .map_err(BleError::from),
        )
    }

    async fn get_characteristic_writes(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError> {
        self.0
            .get_characteristic_writes(device, service, characteristic)
            .await
            .map_err(BleError::from)
    }

    async fn wait_for_characteristic_read(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError> {
        self.0
            .wait_for_characteristic_read(device, service, characteristic)
            .await
            .map_err(BleError::from)
    }

    async fn stop_server(&self) -> Result<(), BleError> {
        self.0.stop_server().await.map_err(BleError::from)
    }
}
