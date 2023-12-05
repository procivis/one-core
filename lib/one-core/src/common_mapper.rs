use std::iter::IntoIterator;
use std::sync::Arc;

use fmap::Functor;
use serde::{Deserialize, Deserializer};
use shared_types::{DidId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::{CoreConfig, ExchangeType};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::organisation::Organisation;
use crate::provider::did_method::dto::DidDocumentDTO;
use crate::provider::transport_protocol::openid4vc::OpenID4VCParams;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::{model::common::GetListResponse, service::error::ServiceError};

pub fn convert_inner<'a, T, A>(outer: T) -> T::Mapped
where
    T: Functor<'a, A>,
    T::Inner: Into<A>,
{
    outer.fmap(Into::into)
}

pub fn convert_inner_of_inner<'a, T, K, A: 'a>(outer: T) -> T::Mapped
where
    T: Functor<'a, K>,
    T::Inner: Functor<'a, A, Mapped = K>,
    <T::Inner as Functor<'a, A>>::Inner: Into<A>,
{
    outer.fmap(|val| val.fmap(Into::into))
}

pub fn iterable_try_into<T, C, R>(input: C) -> Result<R, <C::Item as TryInto<T>>::Error>
where
    C: IntoIterator,
    C::Item: TryInto<T>,
    R: FromIterator<T>,
{
    input.into_iter().map(|item| item.try_into()).collect()
}

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
        values: iterable_try_into(input.values)?,
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
                let did_method = did_method_id_from_value(holder_did_value)?;
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
                    did_method,
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

pub(super) fn did_method_id_from_value(did_value: &DidValue) -> Result<String, ServiceError> {
    let mut parts = did_value.as_str().splitn(3, ':');

    let did_method = parts.nth(1).ok_or(ServiceError::ValidationError(
        "Did method not found".to_string(),
    ))?;
    Ok(did_method.to_uppercase())
}

pub(super) fn did_from_did_document(
    did_document: &DidDocumentDTO,
    organisation: &Organisation,
) -> Result<Did, ServiceError> {
    let now = OffsetDateTime::now_utc();
    let did_method = did_method_id_from_value(&did_document.id)?;

    Ok(Did {
        id: Uuid::new_v4().into(),
        created_date: now,
        last_modified: now,
        name: did_document.id.to_string(),
        did: did_document.id.clone(),
        did_type: DidType::Remote,
        did_method,
        keys: None,
        organisation: Some(organisation.to_owned()),
        deactivated: false,
    })
}
