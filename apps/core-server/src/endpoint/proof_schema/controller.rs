use super::dto::{
    CreateProofSchemaRequestRestDTO, GetProofSchemaQuery, GetProofSchemaResponseRestDTO,
};
use crate::dto::common::{EntityResponseRestDTO, GetProofSchemaListResponseRestDTO};
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;
use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1",
    request_body = CreateProofSchemaRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn post_proof_schema(
    state: State<AppState>,
    Json(request): Json<CreateProofSchemaRequestRestDTO>,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state
        .core
        .proof_schema_service
        .create_proof_schema(request.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating proof schema")
}

#[utoipa::path(
    get,
    path = "/api/proof-schema/v1",
    responses(OkOrErrorResponse<GetProofSchemaListResponseRestDTO>),
    params(GetProofSchemaQuery),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_schemas(
    state: State<AppState>,
    Qs(query): Qs<GetProofSchemaQuery>,
) -> OkOrErrorResponse<GetProofSchemaListResponseRestDTO> {
    let result = state
        .core
        .proof_schema_service
        .get_proof_schema_list(query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "getting proof schemas")
}

#[utoipa::path(
    get,
    path = "/api/proof-schema/v1/{id}",
    responses(OkOrErrorResponse<GetProofSchemaResponseRestDTO>),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn get_proof_schema_detail(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> OkOrErrorResponse<GetProofSchemaResponseRestDTO> {
    let result = state.core.proof_schema_service.get_proof_schema(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof schema")
}

#[utoipa::path(
    delete,
    path = "/api/proof-schema/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
)]
pub(crate) async fn delete_proof_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .proof_schema_service
        .delete_proof_schema(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting proof schema")
}
