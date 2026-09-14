use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::ServiceError;
use proc_macros::endpoint;
use shared_types::{CredentialSchemaId, Permission};

use super::dto::{
    CredentialSchemaResponseRestDTO, CredentialSchemaShareResponseRestDTO,
    CredentialSchemaV2ResponseRestDTO, GetCredentialSchemaQuery, GetCredentialSchemaV2Query,
    ImportCredentialSchemaRequestRestDTO, ImportCredentialSchemaV2RequestRestDTO,
};
use crate::dto::common::{
    EntityResponseRestDTO, GetCredentialSchemasResponseDTO, GetCredentialSchemasV2ResponseDTO,
};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::endpoint::credential_schema::dto::{
    CreateCredentialSchemaRequestRestDTO, CreateCredentialSchemaV2RequestRestDTO,
};
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::CredentialSchemaDelete],
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

#[endpoint(
    permissions = [Permission::CredentialSchemaDetail],
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
    description = "Retrieves detailed information about a credential schema.",
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

#[endpoint(
    permissions = [Permission::CredentialSchemaList],
    get,
    path = "/api/credential-schema/v1",
    responses(OkOrErrorResponse<GetCredentialSchemasResponseDTO>),
    params(GetCredentialSchemaQuery),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "List credential schemas",
    description = "Returns a list of credential schemas in an organization.",
)]
pub(crate) async fn get_credential_schema_list(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetCredentialSchemaQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetCredentialSchemasResponseDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .credential_schema_service
                .get_credential_schema_list(query.try_into()?)
                .await
                .error_while("getting credential schema list")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schemas")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaList],
    get,
    path = "/api/credential-schema/v2",
    responses(OkOrErrorResponse<GetCredentialSchemasV2ResponseDTO>),
    params(GetCredentialSchemaV2Query),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "List credential schemas (v2)",
    description = "Returns a list of credential schemas in an organization in v2 format.",
)]
pub(crate) async fn get_credential_schema_list_v2(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<
        Qs<GetCredentialSchemaV2Query>,
        ErrorResponseRestDTO,
    >,
) -> OkOrErrorResponse<GetCredentialSchemasV2ResponseDTO> {
    let result = async {
        Ok::<_, ServiceError>(
            state
                .core
                .credential_schema_service
                .get_credential_schema_list_v2(query.try_into()?)
                .await
                .error_while("getting credential schema list v2")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schemas v2")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaCreate],
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
            return CreatedOrErrorResponse::from_error(
                &err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .credential_schema_service
        .import_credential_schema(request)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "importing credential schema")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaCreate],
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
        Creates a credential schema, which defines the structure and claims of a
        credential type. Schemas are reusable templates — each credential you issue
        is based on a schema.

        The `format`, `revocationMethod`, and `datatype` values must reference
        configuration instance identifiers from your system configuration.

        Related guide: [Credential schemas](https://docs.procivis.ch/credential-schemas)
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
            return CreatedOrErrorResponse::from_error(
                &err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .credential_schema_service
        .create_credential_schema(request)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating credential schema")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaShare],
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
    with_rejection: WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> CreatedOrErrorResponse<CredentialSchemaShareResponseRestDTO> {
    share_credential_schema_v2(axum::Extension(authorized), state, with_rejection).await
}

#[endpoint(
    permissions = [Permission::CredentialSchemaShare],
    post,
    path = "/api/credential-schema/v2/{id}/share",
    responses(CreatedOrErrorResponse<CredentialSchemaShareResponseRestDTO>),
    params(
        ("id" = CredentialSchemaId, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Share credential schema (v2)",
    description = indoc::formatdoc! {"
        Generates a url to share a credential schema with a mobile verifier using the v2 SSI schema endpoint.
        The mobile verifier can make an HTTP request on the resulting url to preview the shared credential
        schema in v2 format.
    "},
)]
pub(crate) async fn share_credential_schema_v2(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> CreatedOrErrorResponse<CredentialSchemaShareResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .share_credential_schema(&id)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "sharing credential schema")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaDetail],
    get,
    path = "/api/credential-schema/v2/{id}",
    responses(OkOrErrorResponse<CredentialSchemaV2ResponseRestDTO>),
    params(
        ("id" = CredentialSchemaId, Path, description = "Schema id")
    ),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve credential schema (v2)",
    description = "Retrieves detailed information about a credential schema in v2 format, including all formats and per-claim mappings.",
)]
pub(crate) async fn get_credential_schema_v2(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CredentialSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<CredentialSchemaV2ResponseRestDTO> {
    let result = state
        .core
        .credential_schema_service
        .get_credential_schema_v2(&id, None)
        .await;
    OkOrErrorResponse::from_result(result, state, "getting credential schema v2")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaCreate],
    post,
    path = "/api/credential-schema/v2",
    request_body = CreateCredentialSchemaV2RequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create credential schema (v2)",
    description = indoc::formatdoc! {"
        Creates a credential schema (v2), which supports multiple credential formats
        and per-claim technical key mappings.

        The `formats` array is mandatory and must contain at least one entry.
        Each entry specifies a `format` (mandatory) and an optional `ecosystemSchemaId`.

        Claims may include a `mapping` array to specify per-format technical keys
        and namespaces. When no mapping is specified, the claim key is used as the
        technical key. For mdoc formats, the schemaId is used as the default namespace.

        The optional `batchSize` must be at least 2 if specified.
    "},
)]
pub(crate) async fn post_credential_schema_v2(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateCredentialSchemaV2RequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return CreatedOrErrorResponse::from_error(
                &err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .credential_schema_service
        .create_credential_schema_v2(request)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "creating credential schema v2")
}

#[endpoint(
    permissions = [Permission::CredentialSchemaCreate],
    post,
    path = "/api/credential-schema/v2/import",
    request_body = ImportCredentialSchemaV2RequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "credential_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Import credential schema (v2)",
    description = indoc::formatdoc! {"
        Imports a shared credential schema (v2) supporting multiple credential formats
        and per-claim technical key mappings.

        After previewing the credential schema from the
        [share credential schema](../core/share-credential-schema.api.mdx) endpoint, pass
        the schema here, along with the uuid of the mobile verifier's organization,
        to import the credential schema.
    "},
)]
pub(crate) async fn import_credential_schema_v2(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ImportCredentialSchemaV2RequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return CreatedOrErrorResponse::from_error(
                &err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .credential_schema_service
        .import_credential_schema_v2(request)
        .await;
    CreatedOrErrorResponse::from_result(result, state, "importing credential schema v2")
}
