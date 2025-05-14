use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use one_core::service::error::ServiceError;
use shared_types::CertificateId;

use super::dto::CertificateResponseRestDTO;
use crate::dto::error::ErrorResponseRestDTO;
use crate::dto::response::OkOrErrorResponse;
use crate::router::AppState;

#[utoipa::path(
    get,
    path = "/api/certificate/v1/{id}",
    responses(OkOrErrorResponse<CertificateResponseRestDTO>),
    params(
        ("id" = CertificateId, Path, description = "Certificate id")
    ),
    tag = "certificate_management",
    security(
        ("bearer" = [])
    ),
    summary = "Get a certificate",
    description = "Retrieves detailed information about a certificate.",
)]
pub(crate) async fn get_certificate(
    state: State<AppState>,
    WithRejection(Path(id), _): WithRejection<Path<CertificateId>, ErrorResponseRestDTO>,
) -> OkOrErrorResponse<CertificateResponseRestDTO> {
    let result = state.core.certificate_service.get_certificate(id).await;

    match result {
        Ok(value) => match CertificateResponseRestDTO::try_from(value) {
            Ok(value) => OkOrErrorResponse::ok(value),
            Err(error) => {
                tracing::error!("Error while converting certificate response: {:?}", error);
                OkOrErrorResponse::from_service_error(
                    ServiceError::MappingError(error.to_string()),
                    state.config.hide_error_response_cause,
                )
            }
        },
        Err(error) => {
            tracing::error!("Error while getting certificate details: {:?}", error);
            OkOrErrorResponse::from_service_error(error, state.config.hide_error_response_cause)
        }
    }
}
