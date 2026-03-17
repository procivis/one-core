use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::error::ContextWithErrorCode;
use one_core::service::error::{ServiceError, ValidationError};
use proc_macros::endpoint;
use shared_types::{Permission, ProofId};

use super::dto::{
    CreateProofRequestRestDTO, GetProofQuery, PresentationDefinitionResponseRestDTO,
    PresentationDefinitionV2ResponseRestDTO, ProofDetailResponseRestDTO, ShareProofRequestRestDTO,
    ShareProofResponseRestDTO,
};
use crate::dto::common::{EntityResponseRestDTO, GetProofsResponseRestDTO};
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::dto::response::{CreatedOrErrorResponse, EmptyOrErrorResponse, OkOrErrorResponse};
use crate::extractor::Qs;
use crate::router::AppState;

#[endpoint(
    permissions = [Permission::ProofDetail],
    get,
    path = "/api/proof-request/v1/{id}/presentation-definition",
    responses(OkOrErrorResponse<PresentationDefinitionResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Presentation definition (V1)",
    description = indoc::formatdoc! {"
        For wallets; after a wallet connects to a verifier's request for proof via the
        [Handle Invitation](../core/handle-invitation.api.mdx) endpoint, the presentation
        definition endpoint takes the resulting `proofId` and filters the wallet, returning
        credentials which match the verifier's request.

        This version uses Presentation Exchange as the query language.
    "},
)]
pub(crate) async fn get_proof_presentation_definition(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<PresentationDefinitionResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .get_proof_presentation_definition(&id)
        .await
        .error_while("getting presentation definition")
        .map_err(ServiceError::from);
    OkOrErrorResponse::from_result_fallible(result, state, "getting presentation definition")
}

#[endpoint(
    permissions = [Permission::ProofDetail],
    get,
    path = "/api/proof-request/v2/{id}/presentation-definition",
    responses(OkOrErrorResponse<PresentationDefinitionV2ResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Presentation definition (V2)",
    description = indoc::formatdoc! {"
        For wallets; after a wallet connects to a verifier's request for proof via the
        [Handle Invitation](../core/handle-invitation.api.mdx) endpoint, the presentation
        definition endpoint takes the resulting `proofId` and filters the wallet,
        returning credentials which match the verifier's request.

        This version uses DCQL as the query language.
    "},
)]
pub(crate) async fn get_proof_presentation_definition_v2(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<PresentationDefinitionV2ResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .get_proof_presentation_definition_v2(&id)
        .await
        .error_while("getting presentation definition V2")
        .map_err(ServiceError::from);
    OkOrErrorResponse::from_result_fallible(result, state, "getting presentation definition v2")
}

#[endpoint(
    permissions = [Permission::ProofDetail],
    get,
    path = "/api/proof-request/v1/{id}",
    responses(OkOrErrorResponse<ProofDetailResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Retrieve a proof request",
    description = "Returns detailed information about a proof request.",
)]
pub(crate) async fn get_proof_details(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<ProofDetailResponseRestDTO> {
    let result = state
        .core
        .proof_service
        .get_proof(&id)
        .await
        .error_while("getting proof")
        .map_err(ServiceError::from);
    OkOrErrorResponse::from_result_fallible(result, state, "getting proof")
}

#[endpoint(
    permissions = [Permission::ProofDelete],
    delete,
    path = "/api/proof-request/v1/{id}",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete proof request",
    description = indoc::formatdoc! {"
    Deletes a proof request that has not completed yet. If the request is in
    `REQUESTED` state then the proof is retracted instead, retaining history
    of the interaction.

    Related guide: [Managing Proof Requests](https://docs.procivis.ch/verify/manage-proofs)
"},
)]
pub(crate) async fn delete_proof(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.proof_service.delete_proof(id).await;
    EmptyOrErrorResponse::from_result(result, state, "deleting proof")
}

#[endpoint(
    permissions = [Permission::ProofList],
    get,
    path = "/api/proof-request/v1",
    responses(OkOrErrorResponse<GetProofsResponseRestDTO>),
    params(GetProofQuery),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "List proof requests",
    description = "Returns a list of proof requests in an organization.",
)]
pub(crate) async fn get_proofs(
    state: State<AppState>,
    WithRejection(Qs(query), _): WithRejection<Qs<GetProofQuery>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<GetProofsResponseRestDTO> {
    let result = async {
        let organisation_id = fallback_organisation_id_from_session(query.filter.organisation_id)?;
        Ok::<_, ServiceError>(
            state
                .core
                .proof_service
                .get_proof_list(&organisation_id, query.try_into()?)
                .await
                .error_while("getting proof list")?,
        )
    }
    .await;
    OkOrErrorResponse::from_result(result, state, "getting proofs")
}

#[endpoint(
    permissions = [Permission::ProofIssue],
    post,
    path = "/api/proof-request/v1",
    request_body = CreateProofRequestRestDTO,
    responses(CreatedOrErrorResponse<EntityResponseRestDTO>),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Create a proof request",
    description = indoc::formatdoc! {"
    Creates a proof request, which can then be shared with a wallet holder.

    Choose what information to request (proof schema), an identifier, and
    which verification protocol to use.

    The `protocol` and `transport` values must reference specific configuration
    instances from your system configuration. For `protocol`, reference a configured
    instance of `verificationProtocol`.

    Related guide: [Verifying Presentations](https://docs.procivis.ch/verify)
"},
)]
pub(crate) async fn post_proof(
    state: State<AppState>,
    WithRejection(Json(request), _): WithRejection<
        Json<CreateProofRequestRestDTO>,
        ErrorResponseRestDTO,
    >,
) -> CreatedOrErrorResponse<EntityResponseRestDTO> {
    let result = state.core.proof_service.create_proof(request.into()).await;
    CreatedOrErrorResponse::from_result(result, state, "creating proof")
}

#[endpoint(
    permissions = [Permission::ProofShare],
    post,
    path = "/api/proof-request/v1/{id}/share",
    request_body(
        content((Option<ShareProofRequestRestDTO>)),
        example = json!({ "params": { "clientIdScheme": "redirect_uri" } }),
    ),
    responses(CreatedOrErrorResponse<ShareProofResponseRestDTO>),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Request a proof",
    description = indoc::formatdoc! {"
        Creates a share URL from a proof request. A wallet holder can use this URL to access
        the proof request.

        For proof requests made with OID4VC, a Client ID Scheme can be specified in the params.
        If no scheme is specified the default scheme from the configuration will be used.
    "},
)]
pub(crate) async fn share_proof(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
    request: Result<Json<ShareProofRequestRestDTO>, JsonRejection>,
) -> CreatedOrErrorResponse<ShareProofResponseRestDTO> {
    if let Err(JsonRejection::JsonDataError(error)) = &request {
        return CreatedOrErrorResponse::from_result(
            Err::<ShareProofResponseRestDTO, ServiceError>(
                ValidationError::DeserializationError(error.body_text()).into(),
            ),
            state,
            "sharing proof",
        );
    }

    let result = state
        .core
        .proof_service
        .share_proof(&id, request.unwrap_or_default().0.into())
        .await;
    CreatedOrErrorResponse::from_result(result, state, "sharing proof")
}

#[endpoint(
    permissions = [Permission::ProofClaimsDelete],
    delete,
    path = "/api/proof-request/v1/{id}/claims",
    responses(EmptyOrErrorResponse),
    params(
        ("id" = ProofId, Path, description = "Proof id")
    ),
    tag = "proof_management",
    security(
        ("bearer" = [])
    ),
    summary = "Delete claim data",
    description = indoc::formatdoc! {"
        For the specified proof, permanently deletes all claim data shared by the wallet
        holder. The proof request metadata and related history entries are still accessible.
    "},
)]
pub(crate) async fn delete_proof_claims(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<ProofId>, ErrorResponseRestDTO>,
) -> EmptyOrErrorResponse {
    let result = state.core.proof_service.delete_proof_claims(id).await;
    EmptyOrErrorResponse::from_result(result, state, " deleting proof claims")
}
