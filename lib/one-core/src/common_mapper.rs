use std::iter::IntoIterator;

use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::model::claim::{Claim, ClaimId};
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential::{Credential, CredentialRole, CredentialState, CredentialStateEnum};
use crate::model::credential_schema::CredentialSchema;
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::organisation::Organisation;
use crate::provider::transport_protocol::openid4vc::OpenID4VCParams;
use crate::repository::did_repository::DidRepository;
use crate::{model::common::GetListResponse, service::error::ServiceError};
use dto_mapper::{convert_inner, try_convert_inner};
use serde::{Deserialize, Deserializer};
use shared_types::{DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub fn list_response_into<T, F: Into<T>>(input: GetListResponse<F>) -> GetListResponse<T> {
    GetListResponse::<T> {
        values: convert_inner(input.values),
        total_pages: input.total_pages,
        total_items: input.total_items,
    }
}

pub fn list_response_try_into<T, F: TryInto<T>>(
    input: GetListResponse<F>,
) -> Result<GetListResponse<T>, F::Error> {
    Ok(GetListResponse::<T> {
        values: try_convert_inner(input.values)?,
        total_pages: input.total_pages,
        total_items: input.total_items,
    })
}

pub(crate) fn get_exchange_param_pre_authorization_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get_by_type(ExchangeType::OpenId4Vc)?;

    Ok(Duration::seconds(
        params.pre_authorized_code_expires_in as _,
    ))
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get_by_type(ExchangeType::OpenId4Vc)?;

    Ok(Duration::seconds(params.token_expires_in as _))
}

pub(crate) async fn get_or_create_did(
    did_repository: &dyn DidRepository,
    organisation: &Option<Organisation>,
    holder_did_value: &DidValue,
) -> Result<Did, ServiceError> {
    Ok(
        match did_repository
            .get_did_by_value(holder_did_value, &DidRelations::default())
            .await?
        {
            Some(did) => did,
            None => {
                let id = Uuid::new_v4();
                let did_method = did_method_id_from_value(holder_did_value)?;
                let organisation = organisation.as_ref().ok_or(ServiceError::MappingError(
                    "organisation is None".to_string(),
                ))?;
                let did = Did {
                    id: DidId::from(id),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: format!("holder {id}"),
                    organisation: Some(organisation.to_owned()),
                    did: holder_did_value.to_owned(),
                    did_method,
                    did_type: DidType::Remote,
                    keys: None,
                    deactivated: false,
                };
                did_repository.create_did(did.clone()).await?;
                did
            }
        },
    )
}

pub(super) fn deserialize_with_serde_json<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: for<'a> Deserialize<'a>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value.as_str() {
        None => serde_json::from_value(value).map_err(serde::de::Error::custom),
        Some(buffer) => serde_json::from_str(buffer).map_err(serde::de::Error::custom),
    }
}

pub(super) fn did_method_id_from_value(did_value: &DidValue) -> Result<String, ServiceError> {
    let mut parts = did_value.as_str().splitn(3, ':');

    let did_method = parts.nth(1).ok_or(ServiceError::ValidationError(
        "Did method not found".to_string(),
    ))?;
    Ok(did_method.to_uppercase())
}

pub fn extracted_credential_to_model(
    credential_schema: CredentialSchema,
    claims: Vec<(String, ClaimSchema)>,
    issuer_did: Did,
    holder_did: Did,
) -> Credential {
    let now = OffsetDateTime::now_utc();
    let credential_id = Uuid::new_v4().into();
    Credential {
        id: credential_id,
        created_date: now,
        issuance_date: now,
        last_modified: now,
        deleted_at: None,
        credential: vec![],
        transport: "PROCIVIS_TEMPORARY".to_string(),
        state: Some(vec![CredentialState {
            created_date: now,
            state: CredentialStateEnum::Accepted,
        }]),
        claims: Some(
            claims
                .into_iter()
                .map(|(value, claim_schema)| Claim {
                    id: ClaimId::new_v4(),
                    credential_id,
                    created_date: now,
                    last_modified: now,
                    value,
                    schema: Some(claim_schema),
                })
                .collect(),
        ),
        issuer_did: Some(issuer_did),
        holder_did: Some(holder_did),
        schema: Some(credential_schema),
        redirect_uri: None,
        interaction: None,
        revocation_list: None,
        key: None,
        role: CredentialRole::Verifier,
    }
}
