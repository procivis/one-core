use super::{
    BleError, CharacteristicUUID, CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
    ServiceUUID,
};

#[async_trait::async_trait]
pub trait BleCentral: Send + Sync {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError>;
    async fn start_scan(&self, filter_services: Option<Vec<ServiceUUID>>) -> Result<(), BleError>;
    async fn stop_scan(&self) -> Result<(), BleError>;
    async fn is_scanning(&self) -> Result<bool, BleError>;
    async fn write_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
        write_type: CharacteristicWriteType,
    ) -> Result<(), BleError>;
    async fn read_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<u8>, BleError>;
    async fn connect(&self, peripheral: DeviceAddress) -> Result<u16, BleError>;
    async fn disconnect(&self, peripheral: DeviceAddress) -> Result<(), BleError>;
    async fn get_discovered_devices(&self) -> Result<Vec<PeripheralDiscoveryData>, BleError>;
    async fn subscribe_to_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError>;
    async fn unsubscribe_from_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError>;
    async fn get_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError>;
}
