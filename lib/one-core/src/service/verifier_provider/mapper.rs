use std::collections::HashMap;

use one_dto_mapper::convert_inner;

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

impl From<ProviderTrustCollectionDTO>
    for crate::service::wallet_provider::dto::ProviderTrustCollectionDTO
{
    fn from(value: ProviderTrustCollectionDTO) -> Self {
        Self {
            id: value.id,
            name: value.name,
            logo: value.logo,
            display_name: convert_inner(value.display_name),
            description: convert_inner(value.description),
        }
    }
}

impl From<DisplayNameDTO> for crate::service::wallet_provider::dto::DisplayNameDTO {
    fn from(value: DisplayNameDTO) -> Self {
        Self {
            lang: value.lang,
            value: value.value,
        }
    }
}
