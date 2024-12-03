use serde::Deserialize;

use crate::provider::trust_management::model::TrustEntityByDid;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustAnchorResponseRestDTO {
    pub entities: Vec<TrustEntityByDid>,
}
