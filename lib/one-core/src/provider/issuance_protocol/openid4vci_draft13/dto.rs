use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct OpenID4VPBleData {
    pub key: String,
    pub name: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OpenID4VPMqttQueryParams {
    pub broker_url: Url,
    pub key: String,
    pub topic_id: Uuid,
}
