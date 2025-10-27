use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::{Fields, WalletProviderType};
use crate::model::key::PublicKeyJwk;
use crate::model::organisation::Organisation;
use crate::model::wallet_unit::{WalletUnit, WalletUnitStatus};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;
use crate::service::wallet_provider::dto::RegisterWalletUnitRequestDTO;
use crate::service::wallet_provider::error::WalletProviderError;

pub(crate) fn wallet_unit_from_request(
    request: RegisterWalletUnitRequestDTO,
    organisation: Organisation,
    config: &Fields<WalletProviderType>,
    public_key: Option<&PublicKeyJwk>,
    now: OffsetDateTime,
    nonce: Option<String>,
) -> Result<WalletUnit, ServiceError> {
    let (status, last_issuance) = match &nonce {
        None => (WalletUnitStatus::Active, Some(now)),
        Some(_) => (WalletUnitStatus::Pending, None),
    };
    Ok(WalletUnit {
        id: Uuid::new_v4().into(),
        name: wallet_unit_name(&request, config, now),
        created_date: now,
        last_modified: now,
        last_issuance,
        os: request.os,
        status,
        wallet_provider_name: request.wallet_provider,
        wallet_provider_type: config.r#type.into(),
        authentication_key_jwk: public_key.cloned(),
        nonce,
        organisation: Some(organisation),
    })
}

fn wallet_unit_name(
    request: &RegisterWalletUnitRequestDTO,
    config: &Fields<WalletProviderType>,
    now: OffsetDateTime,
) -> String {
    format!("{}-{}-{}", config.r#type, request.os, now.unix_timestamp())
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
        e => e.into(),
    }
}
