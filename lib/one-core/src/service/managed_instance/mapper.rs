use std::collections::HashMap;

use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use uuid::Uuid;

use super::dto::{
    DisplayNameDTO, EudiWalletGeneralInfo, EudiWalletInfo, EudiWalletInfoConfig,
    ManagedInstanceFilterParamsDTO, RegisterWalletUnitRequestDTO, TokenValidationDTO,
    UserAuthenticationDTO, UserAuthenticationParams, WscdInfo,
};
use super::error::ManagedInstanceError;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::instance::InstanceStatus;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::managed_instance::{ManagedInstance, ManagedInstanceFilterValue};
use crate::model::organisation::Organisation;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, ParsedKey};
use crate::repository::error::DataLayerError;
use crate::service::error::ServiceError;

pub(crate) fn wallet_unit_from_request(
    request: RegisterWalletUnitRequestDTO,
    organisation: Organisation,
    provider_label: &str,
    public_key: Option<&PublicJwk>,
    now: OffsetDateTime,
    nonce: Option<String>,
    user_nonce: Option<String>,
) -> Result<ManagedInstance, ManagedInstanceError> {
    let status = match (&nonce, &user_nonce) {
        (None, None) => InstanceStatus::Active,
        _ => InstanceStatus::Pending,
    };
    Ok(ManagedInstance {
        id: Uuid::new_v4().into(),
        name: format!("{}-{}-{}", provider_label, request.os, now.unix_timestamp()),
        created_date: now,
        last_modified: now,
        last_issuance: None,
        os: request.os,
        status,
        role: request.role,
        provider: request.provider,
        authentication_key_jwk: public_key.cloned(),
        nonce,
        user_nonce,
        user_sub: None,
        verifier_csr: None,
        verifier_signature_ids: None,
        organisation: organisation.into(),
        attestations: Default::default(),
    })
}

pub(crate) fn public_key_from_wallet_unit(
    wallet_unit: &ManagedInstance,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<KeyHandle, ManagedInstanceError> {
    let ParsedKey { key, .. } = key_algorithm_provider
        .parse_jwk(wallet_unit.authentication_key_jwk.as_ref().ok_or(
            ManagedInstanceError::MappingError("Missing public key".to_string()),
        )?)
        .error_while("parsing wallet unit JWK")?;
    Ok(key)
}

pub(super) fn map_already_exists_error(error: DataLayerError) -> ManagedInstanceError {
    match error {
        DataLayerError::AlreadyExists => {
            ManagedInstanceError::WalletUnitAlreadyExists.error_while("creating wallet unit")
        }
        e => e.error_while("creating wallet unit"),
    }
    .into()
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

pub(super) fn params_into_display_names(params: HashMap<String, String>) -> Vec<DisplayNameDTO> {
    params
        .into_iter()
        .map(|(lang, value)| DisplayNameDTO { lang, value })
        .collect()
}

impl TryFrom<ManagedInstanceFilterParamsDTO> for ListFilterCondition<ManagedInstanceFilterValue> {
    type Error = ServiceError;

    fn try_from(value: ManagedInstanceFilterParamsDTO) -> Result<Self, Self::Error> {
        let organisation_id =
            ManagedInstanceFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            ManagedInstanceFilterValue::Name(StringMatch {
                r#match: StringMatchType::StartsWith,
                value: name,
            })
        });

        let ids = value.ids.map(ManagedInstanceFilterValue::Ids);

        let status = value.status.map(ManagedInstanceFilterValue::Status);

        let os = value.os.map(ManagedInstanceFilterValue::Os);

        let attestation = value
            .attestation
            .map(|attestation| {
                let attestation_hash = SHA256.hash_base64(attestation.as_bytes()).map_err(|e| {
                    ServiceError::MappingError(format!(
                        "Could not hash wallet unit attestation: {e}"
                    ))
                })?;
                Ok::<_, ServiceError>(ManagedInstanceFilterValue::AttestationHash(
                    attestation_hash,
                ))
            })
            .transpose()?;

        let provider_names = value
            .provider_names
            .map(ManagedInstanceFilterValue::ProviderName);

        let roles = value.roles.map(ManagedInstanceFilterValue::Role);

        let created_date_after = value.created_date_after.map(|date| {
            ManagedInstanceFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            ManagedInstanceFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let user_sub = value.user_sub.map(|user_sub| {
            ManagedInstanceFilterValue::UserSub(StringMatch {
                r#match: StringMatchType::StartsWith,
                value: user_sub,
            })
        });

        Ok(organisation_id
            & name
            & ids
            & status
            & os
            & roles
            & provider_names
            & attestation
            & created_date_after
            & created_date_before
            & user_sub)
    }
}

impl From<UserAuthenticationParams> for UserAuthenticationDTO {
    fn from(ua: UserAuthenticationParams) -> Self {
        Self {
            required: ua.required,
            identity_provider: ua.identity_provider,
            client_id: ua.client_id,
            redirect_uri: ua.redirect_uri,
            token_validation: Some(TokenValidationDTO {
                aud: ua.token_validation.aud,
                iss: ua.token_validation.iss,
                jwks_uri: ua.token_validation.jwks_uri,
            }),
        }
    }
}
