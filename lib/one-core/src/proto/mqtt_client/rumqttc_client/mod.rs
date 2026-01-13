use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rumqttc::{
    AsyncClient, Event, MqttOptions, Outgoing, Packet, QoS, TlsConfiguration, Transport,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use tracing::warn;
use uuid::Uuid;

use super::{MqttClient, MqttTopic};

#[derive(Debug, Deserialize, Serialize)]
struct Envelope {
    sender_id: Uuid,
    payload: Vec<u8>,
}

struct Topic {
    connected_clients: usize,
    tx: broadcast::Sender<(Vec<u8>, bool)>,
}

impl Topic {
    fn notify(&self, value: Vec<u8>, enveloped: bool) {
        let result = self.tx.send((value, enveloped));
        if let Err(err) = result {
            warn!("MQTT failed to send data: {err}")
        }
    }
}

type Topics = Arc<RwLock<HashMap<String, Topic>>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BrokerAddr {
    host: String,
    port: u16,
}

#[derive(Clone)]
struct Broker {
    id: Uuid,
    client: AsyncClient,
    topics: Topics,
}

type Brokers = Arc<RwLock<HashMap<BrokerAddr, Broker>>>;

#[derive(Default)]
pub struct RumqttcClient {
    brokers: Brokers,
}

impl RumqttcClient {
    fn subscribe_to_broker(&self, broker_addr: &BrokerAddr) -> Broker {
        const PACKET_SIZE_LIMIT: usize = 30 * 1024 * 1024; // 30MB
        let id = Uuid::new_v4();

        let mut mqttoptions = MqttOptions::new(
            format!("one-core-rumqttc-async-{id}"),
            &broker_addr.host,
            broker_addr.port,
        );
        mqttoptions
            .set_transport(Transport::Tls(TlsConfiguration::Native))
            .set_max_packet_size(PACKET_SIZE_LIMIT, PACKET_SIZE_LIMIT);

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

        let topics = Topics::default();

        tokio::spawn({
            let topics = topics.clone();

            async move {
                loop {
                    let event = match eventloop.poll().await {
                        Ok(event) => event,
                        Err(error) => {
                            tracing::error!(%error, "MQTT connection error");
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            continue;
                        }
                    };

                    let p = match event {
                        Event::Outgoing(Outgoing::Disconnect) => {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            break;
                        }
                        Event::Incoming(Packet::Disconnect) => break,
                        Event::Incoming(Packet::Publish(p)) => p,
                        _ => continue,
                    };

                    let msg: Result<Envelope, _> = bincode::deserialize(&p.payload);

                    // ONE-8357: based on whether bincode deserialization succeeds or not, treat the payload as enveloped or not
                    let (payload, enveloped) = match msg {
                        Ok(v) => (v.payload, true),
                        Err(_) => (p.payload.to_vec(), false),
                    };

                    let topics = topics.read().await;

                    let Some(subscription) = topics.get(&p.topic) else {
                        continue;
                    };

                    subscription.notify(payload, enveloped)
                }
            }
        });

        Broker { id, client, topics }
    }
}

#[async_trait::async_trait]
impl MqttClient for RumqttcClient {
    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn subscribe(
        &self,
        host: String,
        port: u16,
        topic: String,
    ) -> anyhow::Result<Box<dyn MqttTopic>> {
        let broker_addr = BrokerAddr { host, port };

        let mut brokers = self.brokers.write().await;
        let broker = match brokers.entry(broker_addr.clone()) {
            Entry::Occupied(broker_entry) => broker_entry.get().clone(),
            Entry::Vacant(vacant_entry) => vacant_entry
                .insert(self.subscribe_to_broker(&broker_addr))
                .clone(),
        };

        let mut topics = broker.topics.write().await;
        let incoming = match topics.entry(topic.clone()) {
            Entry::Occupied(mut topic_entry) => {
                let topic = topic_entry.get_mut();
                topic.connected_clients += 1;
                topic.tx.subscribe()
            }
            Entry::Vacant(vacant_entry) => {
                broker
                    .client
                    .subscribe(topic.clone(), QoS::AtMostOnce)
                    .await
                    .context("failed to subscribe")?;

                let (tx, rx) = broadcast::channel(16);
                vacant_entry.insert(Topic {
                    connected_clients: 1,
                    tx,
                });

                rx
            }
        };

        Ok(Box::new(RumqttcTopic {
            sender_id: broker.id,
            broker_addr,
            topic_name: topic,
            incoming,
            client: broker.client.clone(),
            topics: broker.topics.clone(),
            brokers: self.brokers.clone(),
        }))
    }
}

struct RumqttcTopic {
    sender_id: Uuid,
    broker_addr: BrokerAddr,
    topic_name: String,
    incoming: broadcast::Receiver<(Vec<u8>, bool)>,
    client: AsyncClient,
    topics: Topics,
    brokers: Brokers,
}

impl Drop for RumqttcTopic {
    fn drop(&mut self) {
        let topic_name = self.topic_name.clone();
        let client = self.client.clone();
        let topics = self.topics.clone();

        let broker_addr = self.broker_addr.clone();
        let brokers = self.brokers.clone();

        tokio::spawn(async move {
            let mut topics = topics.write().await;
            let Entry::Occupied(mut topic_entry) = topics.entry(topic_name.clone()) else {
                return;
            };

            let topic = topic_entry.get_mut();
            topic.connected_clients -= 1;
            if topic.connected_clients != 0 {
                return;
            }

            let result = client.unsubscribe(&topic_name).await;
            if let Err(err) = result {
                warn!("failed to unsubscribe from MQTT topic {topic_name}: {err}");
            }
            topic_entry.remove();

            tokio::spawn(async move {
                let mut brokers = brokers.write().await;
                let Entry::Occupied(broker_entry) = brokers.entry(broker_addr) else {
                    return;
                };

                let broker = broker_entry.get().clone(); // just to make borrow checker happy
                let topics = broker.topics.read().await;

                if !topics.is_empty() {
                    return;
                }

                let result = client.disconnect().await;
                if let Err(err) = result {
                    warn!("failed to disconnect MQTT client: {err}");
                }
                broker_entry.remove();
            });
        });
    }
}

#[async_trait::async_trait]
impl MqttTopic for RumqttcTopic {
    #[tracing::instrument(level = "debug", skip(self, payload), err(Debug))]
    async fn send(&self, payload: Vec<u8>, enveloped: bool) -> anyhow::Result<()> {
        let msg = if enveloped {
            bincode::serialize(&Envelope {
                sender_id: self.sender_id,
                payload,
            })
            .context("failed to serialize")?
        } else {
            payload
        };

        self.client
            .publish(&self.topic_name, QoS::AtMostOnce, false, msg)
            .await
            .context("failed to send mqtt message")
    }

    #[tracing::instrument(level = "debug", skip(self), err(Debug))]
    async fn recv(&mut self) -> anyhow::Result<(Vec<u8>, bool)> {
        self.incoming
            .recv()
            .await
            .context("failed to recv mqtt message")
    }
}
