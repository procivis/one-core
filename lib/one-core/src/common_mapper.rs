use std::sync::Arc;

use serde::{Deserialize, Deserializer};
use shared_types::{DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::organisation::Organisation;
use crate::provider::transport_protocol::openid4vc::OpenID4VCParams;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::{model::common::GetListResponse, service::error::ServiceError};

pub fn vector_into<T, F: Into<T>>(input: Vec<F>) -> Vec<T> {
    input.into_iter().map(|item| item.into()).collect()
}

pub fn opt_vector_into<T, F: Into<T>>(input: Option<Vec<F>>) -> Option<Vec<T>> {
    input.map(vector_into)
}

pub fn vector_try_into<T, F: TryInto<T>>(
    input: Vec<F>,
) -> Result<Vec<T>, <F as TryInto<T>>::Error> {
    input.into_iter().map(|item| item.try_into()).collect()
}

// not needed for now, uncomment if necessary
// pub fn vector_ref_into<T, F: Into<T> + Clone>(input: &[F]) -> Vec<T> {
//     input.iter().map(|item| item.clone().into()).collect()
// }

pub fn option_into<U, T: Into<U>>(o: Option<T>) -> Option<U> {
    o.map(Into::into)
}

pub fn list_response_into<T, F: Into<T>>(input: GetListResponse<F>) -> GetListResponse<T> {
    GetListResponse::<T> {
        values: vector_into(input.values),
        total_pages: input.total_pages,
        total_items: input.total_items,
    }
}

pub fn list_response_try_into<T, F: TryInto<T>>(
    input: GetListResponse<F>,
) -> Result<GetListResponse<T>, <F as TryInto<T>>::Error> {
    Ok(GetListResponse::<T> {
        values: vector_try_into(input.values)?,
        total_pages: input.total_pages,
        total_items: input.total_items,
    })
}

pub(crate) fn get_exchange_param_pre_authorization_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get(ExchangeType::OpenId4Vc)?;

    Ok(Duration::seconds(
        params.pre_authorized_code_expires_in as _,
    ))
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params: OpenID4VCParams = config.exchange.get(ExchangeType::OpenId4Vc)?;

    Ok(Duration::seconds(params.token_expires_in as _))
}

pub(crate) async fn get_or_create_did(
    did_repository: &Arc<dyn DidRepository + Send + Sync>,
    organisation: &Option<Organisation>,
    holder_did_value: &DidValue,
) -> Result<Did, ServiceError> {
    Ok(
        match did_repository
            .get_did_by_value(holder_did_value, &DidRelations::default())
            .await
        {
            Ok(did) => did,
            Err(DataLayerError::RecordNotFound) => {
                let organisation = organisation.as_ref().ok_or(ServiceError::MappingError(
                    "organisation is None".to_string(),
                ))?;
                let did = Did {
                    id: DidId::from(Uuid::new_v4()),
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    name: "holder".to_string(),
                    organisation: Some(organisation.to_owned()),
                    did: holder_did_value.to_owned(),
                    did_method: "KEY".to_string(),
                    did_type: DidType::Remote,
                    keys: None,
                    deactivated: false,
                };
                did_repository.create_did(did.clone()).await?;
                did
            }
            Err(e) => {
                return Err(ServiceError::from(e));
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
