use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::dto::common::{EntityResponseRestDTO, GetCredentialSchemaResponseDTO};
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::credential_schema::dto::CreateCredentialSchemaRequestRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

use super::dto::{CredentialSchemaResponseRestDTO, GetCredentialSchemaQuery};

#[utoipa::path(
    delete,
    path = "/api/credential-schema/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_credential_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
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
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<CredentialSchemaResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schema")
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1",
    responses(OkOrErrorResponse<GetCredentialSchemaResponseDTO>),
    params(GetCredentialSchemaQuery),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_credential_schema_list(
    state: State<AppState>,
    Qs(query): Qs<GetCredentialSchemaQuery>,
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
    Json(request): Json<CreateCredentialSchemaRequestRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .create_credential_schema(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating credential schema")
}
