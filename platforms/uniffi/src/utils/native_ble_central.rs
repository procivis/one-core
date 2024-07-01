use std::sync::Arc;

use dto_mapper::convert_inner_of_inner;
use one_core::provider::bluetooth_low_energy::{
    BleError, CharacteristicUUID, CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
    ServiceUUID,
};

pub struct BleCentralWrapper(pub Arc<dyn crate::BleCentral>);

#[async_trait::async_trait]
impl one_core::provider::bluetooth_low_energy::ble_central::BleCentral for BleCentralWrapper {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError> {
        self.0.is_adapter_enabled().await.map_err(BleError::from)
    }

    async fn start_scan(&self, filter_services: Option<Vec<ServiceUUID>>) -> Result<(), BleError> {
        self.0
            .start_scan(filter_services)
            .await
            .map_err(BleError::from)
    }

    async fn stop_scan(&self) -> Result<(), BleError> {
        self.0.stop_scan().await.map_err(BleError::from)
    }

    async fn is_scanning(&self) -> Result<bool, BleError> {
        self.0.is_scanning().await.map_err(BleError::from)
    }

    async fn write_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
        write_type: CharacteristicWriteType,
    ) -> Result<(), BleError> {
        self.0
            .write_data(
                peripheral,
                service,
                characteristic,
                data.to_owned(),
                write_type.into(),
            )
            .await
            .map_err(BleError::from)
    }

    async fn read_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<u8>, BleError> {
        self.0
            .read_data(peripheral, service, characteristic)
            .await
            .map_err(BleError::from)
    }

    async fn connect(&self, peripheral: DeviceAddress) -> Result<u16, BleError> {
        self.0.connect(peripheral).await.map_err(BleError::from)
    }

    async fn disconnect(&self, peripheral: DeviceAddress) -> Result<(), BleError> {
        self.0.disconnect(peripheral).await.map_err(BleError::from)
    }

    async fn get_discovered_devices(&self) -> Result<Vec<PeripheralDiscoveryData>, BleError> {
        convert_inner_of_inner(
            self.0
                .get_discovered_devices()
                .await
                .map_err(BleError::from),
        )
    }
    async fn subscribe_to_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError> {
        self.0
            .subscribe_to_characteristic_notifications(peripheral, service, characteristic)
            .await
            .map_err(BleError::from)
    }

    async fn unsubscribe_from_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError> {
        self.0
            .unsubscribe_from_characteristic_notifications(peripheral, service, characteristic)
            .await
            .map_err(BleError::from)
    }

    async fn get_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError> {
        self.0
            .get_notifications(peripheral, service, characteristic)
            .await
            .map_err(BleError::from)
    }
}
