use crate::AppState;
use axum::extract::State;
use axum::{http::StatusCode, Json};

use crate::create_credential_schema::create_credential_schema;
use one_core::data_model::CreateCredentialSchemaRequestDTO;

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
