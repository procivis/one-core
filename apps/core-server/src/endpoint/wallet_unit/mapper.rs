use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::model::wallet_unit::WalletUnitFilterValue;
use one_core::service::error::ServiceError;
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use one_dto_mapper::convert_inner;

use super::dto::WalletUnitFilterQueryParamsRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;

impl TryFrom<WalletUnitFilterQueryParamsRestDTO> for ListFilterCondition<WalletUnitFilterValue> {
    type Error = ServiceError;
    fn try_from(value: WalletUnitFilterQueryParamsRestDTO) -> Result<Self, Self::Error> {
        let organisation_id = WalletUnitFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();
        let name = value.name.map(|name| {
            WalletUnitFilterValue::Name(StringMatch {
                r#match: StringMatchType::StartsWith,
                value: name,
            })
        });

        let ids = value.ids.map(WalletUnitFilterValue::Ids);

        let status = value
            .status
            .map(|status| WalletUnitFilterValue::Status(convert_inner(status)));

        let os = value
            .os
            .map(|os_values| WalletUnitFilterValue::Os(convert_inner(os_values)));

        let attestation = if let Some(attestation) = value.attestation {
            let attestation_hash = SHA256.hash_base64(attestation.as_bytes()).map_err(|e| {
                ServiceError::MappingError(format!("Could not hash wallet unit attestation: {e}"))
            })?;
            Some(WalletUnitFilterValue::AttestationHash(attestation_hash))
        } else {
            None
        };

        let wallet_provider_type = value
            .wallet_provider_type
            .map(WalletUnitFilterValue::WalletProviderType);

        Ok(organisation_id & name & ids & status & os & wallet_provider_type & attestation)
    }
}
