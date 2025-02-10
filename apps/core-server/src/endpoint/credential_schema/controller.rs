use axum::extract::{Path, State};
use axum::Json;
use axum_extra::extract::WithRejection;
use shared_types::CredentialSchemaId;

use super::dto::{
    CredentialSchemaResponseRestDTO, CredentialSchemaShareResponseRestDTO,
    GetCredentialSchemaQuery, ImportCredentialSchemaRequestRestDTO,
};
use crate::dto::common::{EntityResponseRestDTO, GetCredentialSchemasResponseDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::credential_schema::dto::CreateCredentialSchemaRequestRestDTO;
use crate::extractor::Qs;
use crate::router::AppState;

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
    summary = "Delete a credential schema",
    description = "Deletes a credential schema.",
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
    summary = "Retrieve credential schema",
    description = "Retrieves detailed information on a credential schema.",
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

#[utoipa::path(
    get,
    path = "/api/credential-schema/v1",
    responses(OkOrErrorResponse<GetCredentialSchemasResponseDTO>),
    params(GetCredentialSchemaQuery),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "List credential schemas",
    description = "Returns a list of credential schemas in an organization. See the [guidelines](../api/guidelines.mdx) for handling list endpoints.",
)]
pub(crate) async fn get_credential_schema_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetCredentialSchemaQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetCredentialSchemasResponseDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema_list(query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schemas")
}

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1/import",
    request_body = ImportCredentialSchemaRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Import credential schema",
    description = indoc::formatdoc! {"
        Imports a shared credential schema to a mobile verifier, for use in
        constructing proof schemas.

        After previewing the credential schema from the
        [share credential schema](../core/share-credential-schema.api.mdx) endpoint, pass
        the schema here, along with the uuid of the mobile verifier's organization,
        to import the credential schema.
    "},
)]
pub(crate) async fn import_credential_schema(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ImportCredentialSchemaRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return CreatedOrErrorResponse::from_service_error(
                err,
                state.config.hide_error_response_cause,
            )
        }
    };
    let result = state
        .core
        .credential_schema_service
        .import_credential_schema(request)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "importing credential schema")
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
    summary = "Create credential schema",
    description = indoc::formatdoc! {"
        Creates a credential schema, for issuing credentials.

        The `format`, `revocationMethod` and `datatype` values must
        reference specific configuration instances from your system
        configuration. This is because the system allows multiple
        configurations of the same type.

        Related guide: [Credential schemas](../api/credentialSchemas.mdx)
    "},
)]
pub(crate) async fn post_credential_schema(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateCredentialSchemaRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return CreatedOrErrorResponse::from_service_error(
                err,
                state.config.hide_error_response_cause,
            )
        }
    };
    let result = state
        .core
        .credential_schema_service
        .create_credential_schema(request)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating credential schema")
}

#[utoipa::path(
    post,
    path = "/api/credential-schema/v1/{id}/share",
    responses(CreatedOrErrorResponse<CredentialSchemaShareResponseRestDTO>),
    params(
        ("id" = CredentialSchemaId, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Share credential schema",
    description = indoc::formatdoc! {"
        Generates a url to share a credential schema with a mobile verifier.
        The mobile verifier can make an HTTP request on the resulting url to preview the shared credential
        schema and [import](../core/import-credential-schema.api.mdx) it to use it in proof schema creation.
    "},
)]
pub(crate) async fn share_credential_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<CredentialSchemaShareResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .share_credential_schema(&id)
        .await;
    OkOrErrorResponse::from_result(result, state, "sharing credential schema")
}
