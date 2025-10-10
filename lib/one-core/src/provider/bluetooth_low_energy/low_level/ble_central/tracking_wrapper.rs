use std::sync::Arc;

use dashmap::DashSet;

use super::super::dto::{
    CharacteristicUUID, CharacteristicWriteType, DeviceAddress, PeripheralDiscoveryData,
    ServiceUUID,
};
use super::BleCentral;
use crate::provider::bluetooth_low_energy::BleError;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct SubscriptionKey {
    peripheral: DeviceAddress,
    service: ServiceUUID,
    characteristic: CharacteristicUUID,
}

/// A wrapper around BleCentral that tracks connections and subscriptions for automatic cleanup
#[derive(Clone)]
pub struct TrackingBleCentral {
    pub(crate) inner: Arc<dyn BleCentral>,
    connected_devices: Arc<DashSet<DeviceAddress>>,
    subscriptions: Arc<DashSet<SubscriptionKey>>,
}

impl TrackingBleCentral {
    pub fn new(inner: Arc<dyn BleCentral>) -> Self {
        Self {
            inner,
            connected_devices: Arc::new(DashSet::new()),
            subscriptions: Arc::new(DashSet::new()),
        }
    }

    /// Stop scanning and clean up all tracked connections and subscriptions
    pub async fn teardown(&self) -> Result<(), BleError> {
        // Stop scanning
        if let Ok(true) = self.inner.is_scanning().await
            && let Err(err) = self.inner.stop_scan().await
        {
            tracing::warn!("Failed to stop scanning during teardown: {err}");
        }

        // Unsubscribe from all characteristics
        let subscriptions: Vec<_> = self
            .subscriptions
            .iter()
            .map(|entry| entry.clone())
            .collect();

        tracing::debug!("teardown subscriptions: {:?}", subscriptions);
        for sub in subscriptions {
            if let Err(err) = self
                .inner
                .unsubscribe_from_characteristic_notifications(
                    sub.peripheral.clone(),
                    sub.service.clone(),
                    sub.characteristic.clone(),
                )
                .await
            {
                tracing::warn!("Failed to unsubscribe from characteristic during teardown: {err}");
            }
        }

        // Disconnect from all devices
        let devices: Vec<_> = self
            .connected_devices
            .iter()
            .map(|entry| entry.clone())
            .collect();

        tracing::debug!("teardown devices: {:?}", devices);
        for device in devices {
            if let Err(err) = self.inner.disconnect(device.clone()).await {
                tracing::warn!("Failed to disconnect device during teardown: {err}");
            }
        }

        // Clear the tracked resources
        self.connected_devices.clear();
        self.subscriptions.clear();

        Ok(())
    }
}

#[async_trait::async_trait]
impl BleCentral for TrackingBleCentral {
    async fn is_adapter_enabled(&self) -> Result<bool, BleError> {
        self.inner.is_adapter_enabled().await
    }

    async fn start_scan(&self, filter_services: Option<Vec<ServiceUUID>>) -> Result<(), BleError> {
        self.inner.start_scan(filter_services).await
    }

    async fn stop_scan(&self) -> Result<(), BleError> {
        self.inner.stop_scan().await
    }

    async fn is_scanning(&self) -> Result<bool, BleError> {
        self.inner.is_scanning().await
    }

    async fn write_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
        data: &[u8],
        write_type: CharacteristicWriteType,
    ) -> Result<(), BleError> {
        self.inner
            .write_data(peripheral, service, characteristic, data, write_type)
            .await
    }

    async fn read_data(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<u8>, BleError> {
        self.inner
            .read_data(peripheral, service, characteristic)
            .await
    }

    async fn connect(&self, peripheral: DeviceAddress) -> Result<u16, BleError> {
        let result = self.inner.connect(peripheral.clone()).await;
        if result.is_ok() {
            self.connected_devices.insert(peripheral);
        }
        result
    }

    async fn disconnect(&self, peripheral: DeviceAddress) -> Result<(), BleError> {
        let result = self.inner.disconnect(peripheral.clone()).await;
        if result.is_ok() {
            self.connected_devices.remove(&peripheral);
            // Also remove any subscriptions for this device
            self.subscriptions
                .retain(|sub| sub.peripheral != peripheral);
        }
        result
    }

    async fn get_discovered_devices(&self) -> Result<Vec<PeripheralDiscoveryData>, BleError> {
        self.inner.get_discovered_devices().await
    }

    async fn subscribe_to_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError> {
        let result = self
            .inner
            .subscribe_to_characteristic_notifications(
                peripheral.clone(),
                service.clone(),
                characteristic.clone(),
            )
            .await;

        if result.is_ok() {
            let key = SubscriptionKey {
                peripheral,
                service,
                characteristic,
            };
            self.subscriptions.insert(key);
        }
        result
    }

    async fn unsubscribe_from_characteristic_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<(), BleError> {
        let result = self
            .inner
            .unsubscribe_from_characteristic_notifications(
                peripheral.clone(),
                service.clone(),
                characteristic.clone(),
            )
            .await;

        if result.is_ok() {
            let key = SubscriptionKey {
                peripheral,
                service,
                characteristic,
            };
            self.subscriptions.remove(&key);
        }
        result
    }

    async fn get_notifications(
        &self,
        peripheral: DeviceAddress,
        service: ServiceUUID,
        characteristic: CharacteristicUUID,
    ) -> Result<Vec<Vec<u8>>, BleError> {
        self.inner
            .get_notifications(peripheral, service, characteristic)
            .await
    }
}
