use dto_mapper::From;
use one_core::service::error::ServiceError;
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::{IntoParams, IntoResponses, ToSchema};
use uuid::Uuid;

use crate::endpoint::{
    credential::dto::CredentialListItemResponseRestDTO,
    credential_schema::dto::CredentialSchemaListItemResponseRestDTO,
    did::dto::DidListItemResponseRestDTO, key::dto::KeyListItemResponseRestDTO,
    proof::dto::ProofListItemResponseRestDTO,
    proof_schema::dto::GetProofSchemaListItemResponseRestDTO,
};

use super::error::ErrorResponseRestDTO;

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
// ToSchema is properly generated thanks to that
#[aliases(
    GetProofsResponseRestDTO = GetListResponseRestDTO<ProofListItemResponseRestDTO>,
    GetCredentialSchemaResponseDTO = GetListResponseRestDTO<CredentialSchemaListItemResponseRestDTO>,
    GetDidsResponseRestDTO = GetListResponseRestDTO<DidListItemResponseRestDTO>,
    GetCredentialsResponseDTO = GetListResponseRestDTO<CredentialListItemResponseRestDTO>,
    GetProofSchemaListResponseRestDTO = GetListResponseRestDTO<GetProofSchemaListItemResponseRestDTO>,
    GetKeyListResponseRestDTO = GetListResponseRestDTO<KeyListItemResponseRestDTO>)]
pub struct GetListResponseRestDTO<T>
where
    T: Clone + fmt::Debug + Serialize,
{
    pub values: Vec<T>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct GetListQueryParams<T: for<'a> ToSchema<'a>> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    #[param(inline)]
    pub sort: Option<T>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    pub name: Option<String>,
    pub organisation_id: String,
    // It is required to rename fields in swagger which are of type vector to <name>[]
    #[param(rename = "exact[]", value_type = Option::<Vec::<String>>)]
    pub exact: Option<Vec<ExactColumn>>,
}

#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListQueryParamsRest<Filter: IntoParams, SortColumn: for<'a> ToSchema<'a>> {
    // pagination
    pub page: u32,
    pub page_size: u32,

    // sorting
    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    // filtering
    #[serde(flatten)]
    pub filter: Filter,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, From)]
#[convert(into = "one_core::model::common::SortDirection")]
pub enum SortDirection {
    #[serde(rename = "ASC")]
    Ascending,
    #[serde(rename = "DESC")]
    Descending,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, From)]
#[convert(into = "one_core::model::common::ExactColumn")]
pub enum ExactColumn {
    #[serde(rename = "name")]
    Name,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct EntityResponseRestDTO {
    pub id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[convert(from = "one_core::model::common::EntityShareResponseDTO")]
#[serde(rename_all = "camelCase")]
pub struct EntityShareResponseRestDTO {
    pub url: String,
}

#[derive(IntoResponses)]
pub enum OkOrErrorResponse<T: for<'a> ToSchema<'a>> {
    #[response(status = 200, description = "OK")]
    Ok(#[to_schema] T),
    #[response(status = 401, description = "Unauthorized")]
    Unauthorized,
    #[response(status = 400, description = "Bad Request")]
    BadRequest(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 404, description = "Entity Not Found")]
    NotFound(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 500, description = "Internal error")]
    ServerError(#[to_schema] ErrorResponseRestDTO),
}

impl<T> OkOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    pub fn ok(value: impl Into<T>) -> Self {
        Self::Ok(value.into())
    }

    pub fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        let error: ErrorResponseRestDTO = ErrorResponseRestDTO::from(error).hide_cause(hide_cause);

        match &error.error {
            ServiceError::EntityNotFound(_) | ServiceError::NotFound => Self::NotFound(error),
            ServiceError::Validation(_) | ServiceError::BusinessLogic(_) => Self::BadRequest(error),
            _ => Self::ServerError(error),
        }
    }
}

impl<T> axum::response::IntoResponse for OkOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        match self {
            Self::Ok(body) => (StatusCode::OK, Json(body)).into_response(),

            Self::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, Json(error)).into_response(),
            Self::NotFound(error) => (StatusCode::NOT_FOUND, Json(error)).into_response(),
            Self::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
            }
        }
    }
}

#[derive(IntoResponses)]
pub enum CreatedOrErrorResponse<T: for<'a> ToSchema<'a>> {
    #[response(status = 201, description = "Created")]
    Created(#[to_schema] T),
    #[response(status = 401, description = "Unauthorized")]
    Unauthorized,
    #[response(status = 400, description = "Bad Request")]
    BadRequest(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 404, description = "Entity Not Found")]
    NotFound(#[to_schema] ErrorResponseRestDTO),
    #[response(status = 500, description = "Internal error")]
    ServerError(#[to_schema] ErrorResponseRestDTO),
}

impl<T> CreatedOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    pub fn created(value: impl Into<T>) -> Self {
        Self::Created(value.into())
    }

    pub fn from_service_error(error: ServiceError, hide_cause: bool) -> Self {
        let error: ErrorResponseRestDTO = ErrorResponseRestDTO::from(error).hide_cause(hide_cause);

        match &error.error {
            ServiceError::EntityNotFound(_) | ServiceError::NotFound => Self::NotFound(error),
            ServiceError::Validation(_) | ServiceError::BusinessLogic(_) => Self::BadRequest(error),
            _ => Self::ServerError(error),
        }
    }
}

impl<T> axum::response::IntoResponse for CreatedOrErrorResponse<T>
where
    T: for<'a> ToSchema<'a> + Serialize,
{
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;

        match self {
            Self::Created(body) => (StatusCode::CREATED, Json(body)).into_response(),

            Self::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, Json(error)).into_response(),
            Self::NotFound(error) => (StatusCode::NOT_FOUND, Json(error)).into_response(),
            Self::ServerError(error) => {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
            }
        }
    }
}
