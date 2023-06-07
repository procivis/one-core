use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::{http::StatusCode, Json};
use sea_orm::DbErr;
use serde_json::{json, Value};

use crate::create_credential_schema::create_credential_schema;
use crate::data_model::CreateCredentialSchemaRequestDTO;
use crate::get_credential_schemas::*;
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
            ("id" = u32, Path, description = "Schema id")
        )
    )]
pub(crate) async fn delete_credential_schema(
    state: State<AppState>,
    Path(id): Path<u32>,
) -> StatusCode {
    let result = super::delete_credential_schema::delete_credential_schema(&state.db, id).await;

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
        path = "/api/credential-schema/v1",
        responses(
            (status = 200, description = "OK"),
            (status = 500, description = "Server error"),
        ),
        params(
            GetCredentialSchemaQuery
        )
    )]
pub(crate) async fn get_credential_schema(
    state: State<AppState>,
    Query(query): Query<GetCredentialSchemaQuery>,
) -> Response {
    let result = get_credential_schemas(&state.db, query.page, query.page_size).await;

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
        )
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
    delete,
    path = "/api/proof-schema/v1/{id}",
    responses(
        (status = 204, description = "Deleted"),
        (status = 404, description = "Schema not found"),
        (status = 500, description = "Server error"),
    ),
    params(
        ("id" = u32, Path, description = "Schema id")
    )
)]
pub(crate) async fn delete_proof_schema(state: State<AppState>, Path(id): Path<u32>) -> StatusCode {
    let result = super::delete_proof_schema::delete_proof_schema(&state.db, id).await;

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
    )
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
