use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use rumqttc::{
    AsyncClient, AsyncClientBuilder, Event, MqttOptions, NetworkOptions, Packet, PublishOptions,
    QoS, Transport,
};
use uuid::Uuid;

use crate::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(super) struct MqttConnectionKey {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub use_tls: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum MqttConnectionError {
    #[error("Connection timeout")]
    ConnectionTimeout,
    #[error("Connection closed")]
    ConnectionClosed,
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for MqttConnectionError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::ConnectionTimeout | Self::ConnectionClosed => ErrorCode::BR_0349,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

type PendingPuback =
    Arc<Mutex<Option<tokio::sync::oneshot::Sender<Result<(), MqttConnectionError>>>>>;

struct MqttConnection {
    client: AsyncClient,
    pending_puback: PendingPuback,
}

impl MqttConnection {
    fn new(
        mut opts: MqttOptions,
        connection_timeout_secs: u64,
        key: MqttConnectionKey,
        pool: Arc<DashMap<MqttConnectionKey, Arc<Self>>>,
    ) -> Arc<Self> {
        let mut network_opts = NetworkOptions::new();
        network_opts.set_connection_timeout(connection_timeout_secs);
        opts.set_network_options(network_opts);

        let pending_puback: PendingPuback = Arc::new(Mutex::new(None));
        let (client, mut eventloop) = AsyncClientBuilder::new(opts).capacity(16).build();

        let pending_clone = pending_puback.clone();
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::PubAck(_))) => {
                        if let Ok(mut guard) = pending_clone.lock()
                            && let Some(tx) = guard.take()
                        {
                            drop(tx.send(Ok(())));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("MQTT connection to {}:{} closed: {e}", key.host, key.port);
                        if let Ok(mut guard) = pending_clone.lock()
                            && let Some(tx) = guard.take()
                        {
                            drop(tx.send(Err(MqttConnectionError::Nested(e.error_while("")))));
                        };
                        pool.remove(&key);
                        break;
                    }
                }
            }
        });

        Arc::new(Self {
            client,
            pending_puback,
        })
    }

    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), MqttConnectionError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let mut guard = self
                .pending_puback
                .lock()
                .map_err(|_| MqttConnectionError::ConnectionClosed)?;
            *guard = Some(tx);
        }

        if let Err(e) = self
            .client
            .publish(topic, payload, PublishOptions::new(QoS::AtLeastOnce))
            .await
        {
            {
                let mut guard = self
                    .pending_puback
                    .lock()
                    .map_err(|_| MqttConnectionError::ConnectionClosed)?;
                drop(guard.take());
            }
            return Err(MqttConnectionError::Nested(
                e.error_while("getting pending puback lock"),
            ));
        }

        match rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(MqttConnectionError::ConnectionClosed),
        }
    }
}

pub(super) struct MqttConnectionPool {
    connections: Arc<DashMap<MqttConnectionKey, Arc<MqttConnection>>>,
}

impl MqttConnectionPool {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
        }
    }

    pub async fn publish(
        &self,
        key: MqttConnectionKey,
        opts: MqttOptions,
        connection_timeout_secs: u64,
        topic: &str,
        payload: Vec<u8>,
    ) -> Result<(), MqttConnectionError> {
        let conn = self
            .connections
            .entry(key.clone())
            .or_insert_with(|| {
                MqttConnection::new(
                    opts,
                    connection_timeout_secs,
                    key.clone(),
                    self.connections.clone(),
                )
            })
            .clone(); // clone Arc to release the DashMap shard lock before awaiting
        match conn.publish(topic, payload.clone()).await {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!("Cached MQTT publish failed, reconnecting: {e}");
                self.connections.remove(&key);
                Err(MqttConnectionError::Nested(
                    e.error_while("publishing to MQTT"),
                ))
            }
        }
    }
}

pub(super) fn build_mqtt_options(key: &MqttConnectionKey) -> MqttOptions {
    let client_id = format!("one-core-{}", Uuid::new_v4());
    let broker = rumqttc::Broker::tcp(&key.host, key.port);
    let mut opts = MqttOptions::new(client_id, broker);
    opts.set_keep_alive(60u16);

    if let Some(username) = &key.username {
        let password = key.password.as_deref().unwrap_or("").as_bytes().to_vec();
        opts.set_credentials(username.to_owned(), password);
    }

    if key.use_tls {
        opts.set_transport(build_tls_transport());
    }

    opts
}

fn build_tls_transport() -> Transport {
    use rumqttc::TlsConfiguration;
    Transport::tls_with_config(TlsConfiguration::default())
}

impl ErrorCodeMixin for rumqttc::ConnectionError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0349
    }
}

impl ErrorCodeMixin for rumqttc::ClientError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0349
    }
}
