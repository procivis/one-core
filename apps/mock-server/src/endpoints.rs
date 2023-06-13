use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use sea_orm::DbErr;
use serde_json::{json, Value};
use uuid::Uuid;
use validator::Validate;

use crate::create_credential_schema::create_credential_schema;
use crate::create_proof_schema::create_proof_schema;
use crate::data_model::{CreateCredentialSchemaRequestDTO, CreateProofSchemaRequestDTO};
use crate::get_credential_schemas::{get_credential_schemas, GetCredentialSchemaQuery};
use crate::get_proof_schemas::GetProofSchemaQuery;
use crate::AppState;

#[utoipa::path(
    delete,
    path = "/api/credential-schema/v1/{id}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "credential_schema_management"
)]
pub(crate) async fn delete_credential_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> StatusCode {
    let result =
        super::delete_credential_schema::delete_credential_schema(&state.db, &id.to_string()).await;

    if let Err(error) = result {
        return match error {
            DbErr::RecordNotFound(_) => StatusCode::NOT_FOUND,
            DbErr::RecordNotUpdated => StatusCode::NOT_FOUND,
            _ => {
                tracing::error!("Error while deleting credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }

    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1/{id}",
    responses(
        (status = 200, description = "OK"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "credential_schema_management"
)]
pub(crate) async fn get_credential_schema_details(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = crate::get_credential_schema_details::get_credential_schema_details(
        &state.db,
        &id.to_string(),
    )
    .await;

    match result {
        Err(error) => match error {
            DbErr::RecordNotFound(message) => (StatusCode::NOT_FOUND, message).into_response(),
            _ => {
                tracing::error!("Error while getting credential: {:?}", error);
                (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
            }
        },
        Ok(value) => (StatusCode::OK, Json::from(value)).into_response(),
    }
}

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1",
    responses(
        (status = 200, description = "OK", body = GetCredentialClaimSchemaResponseDTO),
        (status = 500, description = "Server error"),
    ),
    params(
        GetCredentialSchemaQuery
    ),
    tag = "credential_schema_management"
)]
pub(crate) async fn get_credential_schema(
    state: State<AppState>,
    Query(query): Query<GetCredentialSchemaQuery>,
) -> Response {
    let result = get_credential_schemas(&state.db, query).await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting credential: {:?}", error);
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
        Ok(value) => (StatusCode::OK, Json::from(value)).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1",
    request_body = CreateCredentialSchemaRequestDTO,
    responses(
        (status = 204, description = "Created")
    ),
    tag = "credential_schema_management"
)]
pub(crate) async fn post_credential_schema(
    state: State<AppState>,
    request: Json<CreateCredentialSchemaRequestDTO>,
) -> StatusCode {
    let result = create_credential_schema(&state.db, request.0).await;

    if let Err(error) = result {
        tracing::error!("Error while inserting credential: {:?}", error);
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    path = "/api/proof-schema/v1",
    responses(
        (status = 200, description = "OK", body = ProofSchemaResponseDTO),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Server error"),
    ),
    params(
        GetProofSchemaQuery
    ),
    tag = "proof_schema_management"
)]
pub(crate) async fn get_proof_schemas(
    state: State<AppState>,
    Query(query): Query<GetProofSchemaQuery>,
) -> Response {
    let result = super::get_proof_schemas::get_proof_schemas(&state.db, query).await;

    match result {
        Err(error) => {
            tracing::error!("Error while getting credential: {:?}", error);
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()).into_response()
        }
        Ok(value) => (StatusCode::OK, Json::from(value)).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1",
    request_body = CreateProofSchemaRequestDTO,
    responses(
        (status = 201, description = "Created"),
        (status = 400, description = "Bad request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "proof_schema_management"
)]
pub(crate) async fn post_proof_schema(
    state: State<AppState>,
    Json(request): Json<CreateProofSchemaRequestDTO>,
) -> impl IntoResponse {
    if let Err(e) = request.validate() {
        tracing::error!("Request validation failure: {}", e.to_string());
        return StatusCode::BAD_REQUEST.into_response();
    }

    let result = create_proof_schema(&state.db, request).await;

    match result {
        // Most probably caused by missing constraints - missing claims for example
        Err(DbErr::Exec(e)) => {
            tracing::error!("Database runtime error: {:?}", e);
            StatusCode::BAD_REQUEST.into_response()
        }
        Err(e) => {
            tracing::error!("Error while getting credential: {:?}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Ok(value) => (StatusCode::CREATED, Json::from(value)).into_response(),
    }
}

#[utoipa::path(
    delete,
    path = "/api/proof-schema/v1/{id}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = Uuid, Path, description = "Schema id")
    ),
    tag = "proof_schema_management"
)]
pub(crate) async fn delete_proof_schema(
    state: State<AppState>,
    Path(id): Path<Uuid>,
) -> StatusCode {
    let result = super::delete_proof_schema::delete_proof_schema(&state.db, &id.to_string()).await;

    if let Err(error) = result {
        return match error {
            DbErr::RecordNotFound(_) => StatusCode::NOT_FOUND,
            DbErr::RecordNotUpdated => StatusCode::NOT_FOUND,
            _ => {
                eprintln!("Error while deleting proof schema: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }

    StatusCode::NO_CONTENT
}

#[utoipa::path(
    get,
    path = "/build_info",
    responses(
        (status = 200, description = "Ok")
    ),
    tag = "other"
)]
pub(crate) async fn get_build_info() -> Json<Value> {
    use shadow_rs::shadow;

    shadow!(build);

    Json::from(json!({
        "target": String::from(build::BUILD_RUST_CHANNEL),
        "build_time": String::from(build::BUILD_TIME),
        "branch": String::from(build::BRANCH),
        "tag": String::from(build::TAG),
        "commit": String::from(build::COMMIT_HASH),
        "rust_version": String::from(build::RUST_VERSION),
        "pipeline_id": String::from(build::CI_PIPELINE_ID),
    }))
}
