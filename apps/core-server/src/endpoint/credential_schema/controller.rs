use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::CredentialSchemaId;
use uuid::Uuid;

use crate::dto::common::{EntityResponseRestDTO, GetCredentialSchemaResponseDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{
    declare_utoipa_alias, AliasResponse, CreatedOrErrorResponse, EmptyOrErrorResponse,
    OkOrErrorResponse,
};
use crate::endpoint::credential_schema::dto::CreateCredentialSchemaRequestRestDTO;
use crate::extractor::Qs;

use crate::router::AppState;

use super::dto::{CredentialSchemaResponseRestDTO, GetCredentialSchemaQuery};

#[utoipa::path(
    delete,
    path = "/api/credential-schema/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = CredentialSchemaId, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .credential_schema_service
        .delete_credential_schema(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting credential schema")
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1/{id}",
    responses(OkOrErrorResponse<CredentialSchemaResponseRestDTO>),
    params(
        ("id" = CredentialSchemaId, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<CredentialSchemaResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schema")
}

declare_utoipa_alias!(GetCredentialSchemaResponseDTO);

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1",
    responses(OkOrErrorResponse<AliasResponse<GetCredentialSchemaResponseDTO>>),
    params(GetCredentialSchemaQuery),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_schema_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetCredentialSchemaQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetCredentialSchemaResponseDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema_list(query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schemas")
}

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1",
    request_body = CreateCredentialSchemaRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_credential_schema(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateCredentialSchemaRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .create_credential_schema(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result.map(Uuid::from), state, "creating credential schema")
}
