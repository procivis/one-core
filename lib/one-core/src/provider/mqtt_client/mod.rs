pub mod rumqttc_client;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait MqttTopic: Send + Sync {
    async fn send(&self, bytes: Vec<u8>) -> anyhow::Result<()>;
    async fn recv(&mut self) -> anyhow::Result<Vec<u8>>;
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait MqttClient: Send + Sync {
    async fn subscribe(
        &self,
        url: String,
        port: u16,
        topic: String,
    ) -> anyhow::Result<Box<dyn MqttTopic>>;
}
