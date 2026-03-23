use std::collections::HashMap;

use super::dto::DisplayNameDTO;
use crate::proto::trust_collection::dto::RemoteTrustCollectionInfoDTO;
use crate::service::verifier_provider::dto::ProviderTrustCollectionDTO;

pub(super) fn params_into_display_names(params: HashMap<String, String>) -> Vec<DisplayNameDTO> {
    params
        .into_iter()
        .map(|(lang, value)| DisplayNameDTO { lang, value })
        .collect()
}

impl From<ProviderTrustCollectionDTO> for RemoteTrustCollectionInfoDTO {
    fn from(value: ProviderTrustCollectionDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
        }
    }
}
