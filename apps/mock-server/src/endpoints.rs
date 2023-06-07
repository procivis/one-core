use axum::extract::{Path, State};
use axum::{http::StatusCode, Json};
use sea_orm::DbErr;

use crate::create_credential_schema::create_credential_schema;
use crate::AppState;

use one_core::data_model::CreateCredentialSchemaRequestDTO;

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
                eprintln!("Error while deleting credential: {:?}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
    }

    StatusCode::NO_CONTENT
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
        eprintln!("Error while inserting credential: {:?}", error);
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
