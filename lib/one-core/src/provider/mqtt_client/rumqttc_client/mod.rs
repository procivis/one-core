use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tokio::task::AbortHandle;
use uuid::Uuid;

use super::{MqttClient, MqttTopic};

#[derive(Debug, Deserialize, Serialize)]
struct Envelope {
    id: Uuid,
    payload: Vec<u8>,
}

struct Subscription {
    tx: broadcast::Sender<Vec<u8>>,
}

impl Subscription {
    fn notify(&self, value: Vec<u8>) {
        let _ = self.tx.send(value);
    }
}

type Subscriptions = Arc<RwLock<HashMap<String, Subscription>>>;

pub struct RumqttcClient {
    id: Uuid,
    abort_handle: AbortHandle,
    client: AsyncClient,
    subscriptions: Subscriptions,
}

impl Drop for RumqttcClient {
    fn drop(&mut self) {
        self.abort_handle.abort();
    }
}

impl RumqttcClient {
    pub fn new(host: String, port: u16) -> Self {
        let id = Uuid::new_v4();

        let mqttoptions = MqttOptions::new(format!("rumqttc-async-{id}"), host, port);
        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 10);

        let subscriptions = Subscriptions::default();

        let abort_handle = tokio::spawn({
            let subscriptions = subscriptions.clone();

            async move {
                loop {
                    let Ok(Event::Incoming(Packet::Publish(p))) = eventloop.poll().await else {
                        continue;
                    };

                    let msg: Envelope = match bincode::deserialize(&p.payload) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    if msg.id == id {
                        continue;
                    }

                    let lock = subscriptions.read().await;

                    let Some(subscription) = lock.get(&p.topic) else {
                        continue;
                    };

                    subscription.notify(msg.payload)
                }
            }
        })
        .abort_handle();

        Self {
            id,
            abort_handle,
            client,
            subscriptions,
        }
    }
}

#[async_trait::async_trait]
impl MqttClient for RumqttcClient {
    async fn subscribe(&self, topic: String) -> anyhow::Result<Box<dyn MqttTopic>> {
        let mut lock = self.subscriptions.write().await;

        let incoming = match lock.entry(topic.clone()) {
            Entry::Occupied(occupied_entry) => occupied_entry.get().tx.subscribe(),
            Entry::Vacant(vacant_entry) => {
                self.client
                    .subscribe(topic.clone(), QoS::AtMostOnce)
                    .await
                    .context("failed to subscribe")?;

                let (tx, rx) = broadcast::channel(16);
                vacant_entry.insert(Subscription { tx });

                rx
            }
        };

        Ok(Box::new(RumqttcTopic {
            client_id: self.id,
            topic,
            incoming,
            client: self.client.clone(),
            subscriptions: self.subscriptions.clone(),
        }))
    }
}

struct RumqttcTopic {
    client_id: Uuid,
    topic: String,
    incoming: broadcast::Receiver<Vec<u8>>,
    client: AsyncClient,
    subscriptions: Subscriptions,
}

impl Drop for RumqttcTopic {
    fn drop(&mut self) {
        let topic = self.topic.clone();
        let client = self.client.clone();
        let subscriptions = self.subscriptions.clone();

        tokio::spawn(async move {
            let mut lock = subscriptions.write().await;
            match lock.entry(topic.clone()) {
                Entry::Occupied(subscription) if subscription.get().tx.receiver_count() == 0 => {
                    let _ = client.unsubscribe(&topic).await;
                }
                _ => (),
            }
        });
    }
}

#[async_trait::async_trait]
impl MqttTopic for RumqttcTopic {
    async fn send(&self, payload: Vec<u8>) -> anyhow::Result<()> {
        let msg = bincode::serialize(&Envelope {
            id: self.client_id,
            payload,
        })
        .context("failed to serialize")?;

        self.client
            .publish(&self.topic, QoS::AtMostOnce, false, msg)
            .await
            .context("failed to send mqtt message")
    }

    async fn recv(&mut self) -> anyhow::Result<Vec<u8>> {
        self.incoming
            .recv()
            .await
            .context("failed to recv mqtt message")
    }
}
