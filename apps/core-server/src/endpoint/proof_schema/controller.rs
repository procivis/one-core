use axum::Json;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use proc_macros::require_permissions;
use shared_types::ProofSchemaId;

use super::dto::{
    CreateProofSchemaRequestRestDTO, GetProofSchemaQuery, GetProofSchemaResponseRestDTO,
    ImportProofSchemaRequestRestDTO, ProofSchemaShareResponseRestDTO,
};
use crate::dto::common::{EntityResponseRestDTO, GetProofSchemaListResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::permissions::Permission;
use crate::router::AppState;

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1",
    request_body = CreateProofSchemaRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create proof schema",
    description = indoc::formatdoc! {"
        Creates a proof schema, for creating proof requests.

        Related guide: [Proof schemas](/proof-schemas)
    "},
)]
#[require_permissions(Permission::ProofSchemaCreate)]
pub(crate) async fn post_proof_schema(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateProofSchemaRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
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
    summary = "Retrieve proof schemas",
    description = "Returns a list of proof schemas. See the [filtering](/reference/api/filtering) guide for handling list endpoints.",
)]
#[require_permissions(Permission::ProofSchemaList)]
pub(crate) async fn get_proof_schemas(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetProofSchemaQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetProofSchemaListResponseRestDTO> {
    let organisation_id = query.filter.organisation_id;
    let result = state
        .core
        .proof_schema_service
        .get_proof_schema_list(&organisation_id, query.into())
        .await;
    OkOrErrorResponse::from_result(result, state, "getting proof schemas")
}

#[utoipa::path(
    get,
    path = "/api/proof-schema/v1/{id}",
    responses(OkOrErrorResponse<GetProofSchemaResponseRestDTO>),
    params(
        ("id" = ProofSchemaId, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve proof schema",
    description = "Returns detailed information about a proof schema.",
)]
#[require_permissions(Permission::ProofSchemaDetail)]
pub(crate) async fn get_proof_schema_detail(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofSchemaId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetProofSchemaResponseRestDTO> {
    let result = state.core.proof_schema_service.get_proof_schema(&id).await;
    OkOrErrorResponse::from_result(result, state, "getting proof schema")
}

#[utoipa::path(
    delete,
    path = "/api/proof-schema/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = ProofSchemaId, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete a proof schema",
    description = "Deletes a proof schema.",
)]
#[require_permissions(Permission::ProofSchemaDelete)]
pub(crate) async fn delete_proof_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofSchemaId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state
        .core
        .proof_schema_service
        .delete_proof_schema(&id)
        .await;
    EmptyOrErrorResponse::from_result(result, state, "deleting proof schema")
}

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1/{id}/share",
    responses(CreatedOrErrorResponse<ProofSchemaShareResponseRestDTO>),
    params(
        ("id" = ProofSchemaId, Path, description = "Schema id")
    ),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Share proof schema",
    description = "Generates a url to share a proof schema with a mobile verifier.",
)]
#[require_permissions(Permission::ProofSchemaShare)]
pub(crate) async fn share_proof_schema(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofSchemaId>, ErrorResponseRestDTO>,
) -> CreatedOrErrorResponse<ProofSchemaShareResponseRestDTO> {
    let result = state.core.proof_schema_service.share_proof_schema(id).await;
    CreatedOrErrorResponse::from_result(result, state, "sharing proof schema")
}

#[utoipa::path(
    post,
    path = "/api/proof-schema/v1/import",
    request_body = ImportProofSchemaRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_schema_management",
    security(
        ("bearer" = [])
    ),
    summary = "Import proof schema",
    description = indoc::formatdoc! {"
        Imports a shared proof schema to a mobile verifier, for use in creating proof requests. After previewing
        the proof schema from the [share proof schema](../core/share-proof-schema.api.mdx) endpoint, pass the schema here, along with
        the uuid of the mobile verifier's organization, to import the proof schema.
    "},
)]
#[require_permissions(Permission::ProofSchemaCreate)]
pub(crate) async fn import_proof_schema(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<ImportProofSchemaRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let request = match request.try_into() {
        Ok(request) => request,
        Err(err) => {
            return CreatedOrErrorResponse::from_service_error(
                err,
                state.config.hide_error_response_cause,
            );
        }
    };
    let result = state
        .core
        .proof_schema_service
        .import_proof_schema(request)
        .await
        .map(|resp| EntityResponseRestDTO { id: resp.id.into() });

    CreatedOrErrorResponse::from_result(result, state, "importing proof schema")
}
