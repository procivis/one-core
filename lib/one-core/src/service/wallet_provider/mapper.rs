use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::WalletProviderType;
use crate::error::ErrorCodeMixinExt;
use crate::model::organisation::Organisation;
use crate::model::wallet_unit::{WalletUnit, WalletUnitStatus};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;
use crate::service::wallet_provider::dto::{
    EudiWalletGeneralInfo, EudiWalletInfo, EudiWalletInfoConfig, RegisterWalletUnitRequestDTO,
    WscdInfo,
};
use crate::service::wallet_provider::error::WalletProviderError;

pub(crate) fn wallet_unit_from_request(
    request: RegisterWalletUnitRequestDTO,
    organisation: Organisation,
    wallet_provider_type: WalletProviderType,
    public_key: Option<&PublicJwk>,
    now: OffsetDateTime,
    nonce: Option<String>,
) -> Result<WalletUnit, ServiceError> {
    let status = match &nonce {
        None => WalletUnitStatus::Active,
        Some(_) => WalletUnitStatus::Pending,
    };
    Ok(WalletUnit {
        id: Uuid::new_v4().into(),
        name: format!(
            "{}-{}-{}",
            wallet_provider_type,
            request.os,
            now.unix_timestamp()
        ),
        created_date: now,
        last_modified: now,
        last_issuance: None,
        os: request.os,
        status,
        wallet_provider_name: request.wallet_provider,
        wallet_provider_type: wallet_provider_type.into(),
        authentication_key_jwk: public_key.cloned(),
        nonce,
        organisation: Some(organisation),
        attested_keys: None,
    })
}

pub(crate) fn public_key_from_wallet_unit(
    wallet_unit: &WalletUnit,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<KeyHandle, ServiceError> {
    let ParsedKey { key, .. } = key_algorithm_provider.parse_jwk(
        wallet_unit
            .authentication_key_jwk
            .as_ref()
            .ok_or(ServiceError::MappingError("Missing public key".to_string()))?,
    )?;
    Ok(key)
}

pub(crate) fn map_already_exists_error(error: DataLayerError) -> ServiceError {
    match error {
        DataLayerError::AlreadyExists => WalletProviderError::WalletUnitAlreadyExists.into(),
        e => e.error_while("creating wallet unit").into(),
    }
}

impl From<EudiWalletInfoConfig> for EudiWalletInfo {
    fn from(value: EudiWalletInfoConfig) -> Self {
        Self {
            general_info: EudiWalletGeneralInfo {
                wallet_provider_name: value.provider_name,
                wallet_solution_id: value.solution_id,
                wallet_solution_version: value.solution_version,
            },
            wscd_info: Some(WscdInfo {
                wscd_type: value.wscd_type,
            }),
        }
    }
}
