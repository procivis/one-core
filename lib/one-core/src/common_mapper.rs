use crate::config::data_structure::ExchangeParams::OPENID4VC;
use crate::config::data_structure::{ExchangeParams, ParamsEnum};
use crate::model::did::{Did, DidRelations, DidType};
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::transport_protocol::dto::ProofClaimSchema;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::{
    config::data_structure::CoreConfig, model::common::GetListResponse,
    service::error::ServiceError,
};
use shared_types::{DidId, DidValue};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub fn vector_into<T, F: Into<T>>(input: Vec<F>) -> Vec<T> {
    input.into_iter().map(|item| item.into()).collect()
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

pub(crate) fn get_algorithm_from_key_algorithm(
    signature_type: &str,
    config: &CoreConfig,
) -> Result<String, ServiceError> {
    let algorithm = config
        .key_algorithm
        .get(signature_type)
        .ok_or(ServiceError::MissingSigner(signature_type.to_owned()))?;

    let algorithm = algorithm.params.clone().ok_or(ServiceError::MappingError(
        "Algorithm not found".to_string(),
    ))?;

    match algorithm {
        ParamsEnum::Unparsed(_) => Err(ServiceError::Other(
            "Missing key algorithm in config".to_owned(),
        )),
        ParamsEnum::Parsed(val) => Ok(val.algorithm.value),
    }
}

pub(crate) fn get_exchange_params(
    key_type: &str,
    config: &CoreConfig,
) -> Result<ParamsEnum<ExchangeParams>, ServiceError> {
    let entity_param = config
        .exchange
        .get(key_type)
        .ok_or(ServiceError::MappingError(format!(
            "Missing entity param {}",
            key_type
        )))?;
    entity_param
        .params
        .clone()
        .ok_or(ServiceError::MappingError(format!(
            "Exchange {} not found",
            key_type
        )))
}

pub(crate) fn get_exchange_param_pre_authorization_expires_in(
    config: &CoreConfig,
) -> Result<Duration, ServiceError> {
    let params = get_exchange_params("OPENID4VC", config)?;
    match params {
        ParamsEnum::Parsed(OPENID4VC(val)) => Ok(Duration::seconds(
            val.pre_authorized_code_expires_in
                .ok_or(ServiceError::MappingError(
                    "Pre authorized code expires in not found".to_string(),
                ))?
                .value as i64,
        )),
        _ => Err(ServiceError::Other(
            "Missing key preAuthorizedCodeExpiresIn in config".to_owned(),
        )),
    }
}

pub(crate) fn get_exchange_param_token_expires_in(
    config: &CoreConfig,
) -> Result<u64, ServiceError> {
    let params = get_exchange_params("OPENID4VC", config)?;
    match params {
        ParamsEnum::Parsed(OPENID4VC(val)) => Ok(val
            .token_expires_in
            .ok_or(ServiceError::MappingError(
                "Token expires in not found".to_string(),
            ))?
            .value),
        _ => Err(ServiceError::Other(
            "Missing key tokenExpiresIn in config".to_owned(),
        )),
    }
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

pub fn get_proof_claim_schemas_from_proof(
    value: &Proof,
) -> Result<Vec<ProofClaimSchema>, ServiceError> {
    let interaction_data = value
        .interaction
        .as_ref()
        .ok_or(ServiceError::MappingError(
            "interaction is None".to_string(),
        ))?
        .data
        .to_owned()
        .ok_or(ServiceError::MappingError(
            "interaction data is missing".to_string(),
        ))?;
    let json_data = String::from_utf8(interaction_data)
        .map_err(|e| ServiceError::MappingError(e.to_string()))?;

    let proof_claim_schemas: Vec<ProofClaimSchema> =
        serde_json::from_str(&json_data).map_err(|e| ServiceError::MappingError(e.to_string()))?;
    Ok(proof_claim_schemas)
}
