use std::ops::Deref;
use std::sync::Arc;

use super::super::dto::{
    CharacteristicUUID, ConnectionEvent, DeviceAddress, MacAddress, ServiceDescription, ServiceUUID,
};
use super::BlePeripheral;
use crate::provider::bluetooth_low_energy::BleError;

/// A wrapper around BlePeripheral that provides automatic cleanup functionality
#[derive(Clone)]
pub struct TrackingBlePeripheral {
    pub inner: Arc<dyn BlePeripheral>,
}

impl TrackingBlePeripheral {
    pub fn new(inner: Arc<dyn BlePeripheral>) -> Self {
        Self { inner }
    }

    /// Stop advertising and server, cleaning up all resources
    pub async fn teardown(&self) -> Result<(), BleError> {
        // Stop advertising if currently active
        if let Ok(true) = self.inner.is_advertising().await {
            if let Err(err) = self.inner.stop_advertisement().await {
                tracing::warn!("Failed to stop advertisement during teardown: {err}");
            }
        }

        // Always attempt to stop the server (it should be idempotent)
        if let Err(err) = self.inner.stop_server().await {
            tracing::warn!("Failed to stop server during teardown: {err}");
        }

        Ok(())
    }
}

impl Deref for TrackingBlePeripheral {
    type Target = dyn BlePeripheral;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}

#[async_trait::async_trait]
impl BlePeripheral for TrackingBlePeripheral {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError> {
        self.inner.is_adapter_enabled().await
    }

    async fn start_advertisement(
        &self,
        device_name: Option<String>,
        services: Vec<ServiceDescription>,
    ) -> Result<Option<MacAddress>, BleError> {
        self.inner.start_advertisement(device_name, services).await
    }

    async fn stop_advertisement(&self) -> Result<(), BleError> {
        self.inner.stop_advertisement().await
    }

    async fn is_advertising(&self) -> Result<bool, BleError> {
        self.inner.is_advertising().await
    }

    async fn set_characteristic_data(
        &self,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
    ) -> Result<(), BleError> {
        self.inner
            .set_characteristic_data(service, characteristic, data)
            .await
    }

    async fn notify_characteristic_data(
        &self,
        device_address: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
    ) -> Result<(), BleError> {
        self.inner
            .notify_characteristic_data(device_address, service, characteristic, data)
            .await
    }

    async fn get_connection_change_events(&self) -> Result<Vec<ConnectionEvent>, BleError> {
        self.inner.get_connection_change_events().await
    }

    async fn get_characteristic_writes(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError> {
        self.inner
            .get_characteristic_writes(device, service, characteristic)
            .await
    }

    async fn wait_for_characteristic_read(
        &self,
        device: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError> {
        self.inner
            .wait_for_characteristic_read(device, service, characteristic)
            .await
    }

    async fn stop_server(&self) -> Result<(), BleError> {
        self.inner.stop_server().await
    }
}
