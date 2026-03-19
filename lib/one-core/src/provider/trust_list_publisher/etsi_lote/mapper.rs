use super::dto::{AddEntryParams, CreateTrustListParams};
use crate::provider::trust_list_publisher::error::TrustListPublisherError;

impl TryFrom<serde_json::Value> for AddEntryParams {
    type Error = TrustListPublisherError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(TrustListPublisherError::InvalidParams)
    }
}

impl TryFrom<serde_json::Value> for CreateTrustListParams {
    type Error = TrustListPublisherError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value).map_err(TrustListPublisherError::InvalidParams)
    }
}
