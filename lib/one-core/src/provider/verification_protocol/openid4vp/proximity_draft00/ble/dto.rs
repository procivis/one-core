use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, Debug)]
pub(crate) struct OpenID4VPBleData {
    pub key: String,
    pub name: String,
}
