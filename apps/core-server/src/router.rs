#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{Request, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::routing::{delete, get, patch, post};
use axum::{Extension, Router};
use one_core::config::core_config;
use one_core::OneCore;
use sql_data_provider::{DataLayer, DbConn};
use tower_http::trace::TraceLayer;
use tracing::{info, info_span, Span};
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::build_info;
use crate::{
    dto,
    endpoint::{
        self, config, credential, credential_schema, did, interaction, key, misc, organisation,
        proof, proof_schema, ssi,
    },
    metrics, Config,
};

#[derive(Clone)]
pub(crate) struct AppState {
    pub core: OneCore,
}

pub struct HttpRequestContext {
    pub path: String,
    pub method: String,
    pub request_id: Option<String>,
    pub session_id: Option<String>,
}

tokio::task_local! {
    pub static SENTRY_HTTP_REQUEST: HttpRequestContext;
}

pub async fn start_server(listener: TcpListener, config: Config, db_conn: DbConn) {
    let core_config = core_config::CoreConfig::from_file(&config.config_file).unwrap();

    let core = OneCore::new(
        Arc::new(DataLayer::build(db_conn).await),
        core_config,
        Some(config.core_base_url.to_owned()),
        None,
    )
    .expect("Failed to parse config");

    let state = AppState { core };

    let addr = listener.local_addr().expect("Invalid TCP listener");
    info!("Starting server at http://{addr}");

    let router = router(state, config);

    axum::Server::from_tcp(listener)
        .expect("Failed to create axum server for lister")
        .serve(router.into_make_service())
        .await
        .expect("Failed to start axum server");
}

fn router(state: AppState, config: Config) -> Router {
    let openapi_documentation = gen_openapi_documentation();

    let protected = Router::new()
        .route("/api/config/v1", get(config::controller::get_config))
        .route(
            "/api/credential/v1",
            get(credential::controller::get_credential_list)
                .post(credential::controller::post_credential),
        )
        .route(
            "/api/credential/v1/:id",
            get(credential::controller::get_credential),
        )
        .route(
            "/api/credential/v1/:id/revoke",
            post(credential::controller::revoke_credential),
        )
        .route(
            "/api/credential/v1/:id/share",
            post(credential::controller::share_credential),
        )
        .route(
            "/api/credential/v1/revocation-check",
            post(credential::controller::revocation_check),
        )
        .route(
            "/api/proof-request/v1/:id/share",
            post(proof::controller::share_proof),
        )
        .route(
            "/api/credential-schema/v1/:id",
            delete(credential_schema::controller::delete_credential_schema)
                .get(credential_schema::controller::get_credential_schema),
        )
        .route(
            "/api/credential-schema/v1",
            get(credential_schema::controller::get_credential_schema_list)
                .post(credential_schema::controller::post_credential_schema),
        )
        .route(
            "/api/proof-schema/v1/:id",
            delete(proof_schema::controller::delete_proof_schema)
                .get(proof_schema::controller::get_proof_schema_detail),
        )
        .route("/api/key/v1/:id", get(key::controller::get_key))
        .route(
            "/api/key/v1",
            post(key::controller::post_key).get(key::controller::get_key_list),
        )
        .route(
            "/api/proof-schema/v1",
            get(proof_schema::controller::get_proof_schemas)
                .post(proof_schema::controller::post_proof_schema),
        )
        .route(
            "/api/proof-request/v1",
            post(proof::controller::post_proof).get(proof::controller::get_proofs),
        )
        .route(
            "/api/proof-request/v1/:id",
            get(proof::controller::get_proof_details),
        )
        .route(
            "/api/proof-request/v1/:id/presentation-definition",
            get(proof::controller::get_proof_presentation_definition),
        )
        .route(
            "/api/organisation/v1",
            get(organisation::controller::get_organisations)
                .post(organisation::controller::post_organisation),
        )
        .route(
            "/api/organisation/v1/:id",
            get(organisation::controller::get_organisation),
        )
        .route("/api/did/v1/:id", get(did::controller::get_did))
        .route("/api/did/v1/:id", patch(did::controller::update_did))
        .route("/api/did/v1", get(did::controller::get_did_list))
        .route("/api/did/v1", post(did::controller::post_did))
        .route(
            "/api/interaction/v1/handle-invitation",
            post(interaction::controller::handle_invitation),
        )
        .route(
            "/api/interaction/v1/issuance-submit",
            post(interaction::controller::issuance_submit),
        )
        .route(
            "/api/interaction/v1/issuance-reject",
            post(interaction::controller::issuance_reject),
        )
        .route(
            "/api/interaction/v1/presentation-submit",
            post(interaction::controller::presentation_submit),
        )
        .route(
            "/api/interaction/v1/presentation-reject",
            post(interaction::controller::presentation_reject),
        )
        .layer(middleware::from_fn(bearer_check));

    let unprotected = Router::new()
        .route(
            "/ssi/oidc-issuer/v1/:id/.well-known/openid-credential-issuer",
            get(ssi::controller::oidc_get_issuer_metadata),
        )
        .route(
            "/ssi/oidc-issuer/v1/:id/.well-known/openid-configuration",
            get(ssi::controller::oidc_service_discovery),
        )
        .route(
            "/ssi/oidc-issuer/v1/:id/token",
            post(ssi::controller::oidc_create_token),
        )
        .route(
            "/ssi/oidc-issuer/v1/:id/credential",
            post(ssi::controller::oidc_create_credential),
        )
        .route(
            "/ssi/oidc-verifier/v1/response",
            post(ssi::controller::oidc_verifier_direct_post),
        )
        .route(
            "/ssi/revocation/v1/list/:id",
            get(ssi::controller::get_revocation_list_by_id),
        )
        .route(
            "/ssi/temporary-issuer/v1/connect",
            post(ssi::controller::ssi_issuer_connect),
        )
        .route(
            "/ssi/temporary-issuer/v1/reject",
            post(ssi::controller::ssi_issuer_reject),
        )
        .route(
            "/ssi/temporary-issuer/v1/submit",
            post(ssi::controller::ssi_issuer_submit),
        )
        .route(
            "/ssi/temporary-verifier/v1/connect",
            post(ssi::controller::ssi_verifier_connect),
        )
        .route(
            "/ssi/temporary-verifier/v1/submit",
            post(ssi::controller::ssi_verifier_submit_proof),
        )
        .route(
            "/ssi/temporary-verifier/v1/reject",
            post(ssi::controller::ssi_verifier_reject_proof),
        )
        .route("/metrics", get(metrics::get_metrics));

    let technical_endpoints = Router::new()
        .route("/build-info", get(misc::get_build_info))
        .route("/health", get(misc::health_check));

    Router::new()
        .merge(protected)
        .merge(unprotected)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let context = get_http_request_context(request);
                    info_span!(
                        "http_request",
                        method = context.method,
                        path = context.path,
                        service = "one-core",
                        RequestId = context.request_id,
                        SessionId = context.session_id,
                    )
                })
                .on_request(|request: &Request<_>, _span: &Span| {
                    tracing::debug!(
                        "SERVICE CALL START {} {}",
                        request.method(),
                        request.uri().path()
                    )
                })
                .on_response(|response: &Response<_>, latency: Duration, _span: &Span| {
                    // this will also count itself and the health check which is probably not what we want
                    // TODO: add a separate layer for metrics
                    metrics::track_request_count_and_time(latency.as_millis() as f64);
                    tracing::debug!("SERVICE CALL END {}", response.status())
                }),
        )
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi_documentation))
        .merge(technical_endpoints)
        .layer(middleware::from_fn(sentry_context))
        .layer(Extension(config))
        .with_state(state)
}

#[derive(Debug, Clone)]
pub struct Authorized {}

async fn bearer_check<B>(
    Extension(config): Extension<Config>,
    mut request: Request<B>,
    next: Next<B>,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    let auth_header = if let Some(auth_header) = auth_header {
        auth_header.to_owned()
    } else {
        tracing::warn!("Authorization header not found.");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let mut split = auth_header.split(' ');
    let auth_type = split.next().unwrap_or_default();
    let token = split.next().unwrap_or_default();

    if auth_type == "Bearer" && !token.is_empty() && token == config.auth_token {
        request.extensions_mut().insert(Authorized {});
    } else {
        tracing::warn!("Could not authorize request. Incorrect authorization method or token.");
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

fn get_http_request_context<T>(request: &Request<T>) -> HttpRequestContext {
    let headers = request.headers();
    let request_id = headers
        .get("x-request-id")
        .and_then(|header| header.to_str().ok())
        .map(ToOwned::to_owned);
    let session_id = headers
        .get("x-session-id")
        .and_then(|header| header.to_str().ok())
        .map(ToOwned::to_owned);

    HttpRequestContext {
        path: request.uri().path().to_owned(),
        method: request.method().to_string(),
        request_id,
        session_id,
    }
}

async fn sentry_context<T>(
    request: Request<T>,
    next: Next<T>,
) -> Result<axum::response::Response, StatusCode> {
    SENTRY_HTTP_REQUEST
        .scope(get_http_request_context(&request), async move {
            Ok(next.run(request).await)
        })
        .await
}

fn gen_openapi_documentation() -> utoipa::openapi::OpenApi {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            endpoint::config::controller::get_config,

            endpoint::organisation::controller::post_organisation,
            endpoint::organisation::controller::get_organisation,
            endpoint::organisation::controller::get_organisations,

            endpoint::credential::controller::get_credential,
            endpoint::credential::controller::get_credential_list,
            endpoint::credential::controller::post_credential,
            endpoint::credential::controller::revoke_credential,
            endpoint::credential::controller::share_credential,
            endpoint::credential::controller::revocation_check,

            endpoint::credential_schema::controller::delete_credential_schema,
            endpoint::credential_schema::controller::get_credential_schema,
            endpoint::credential_schema::controller::get_credential_schema_list,
            endpoint::credential_schema::controller::post_credential_schema,

            endpoint::did::controller::get_did,
            endpoint::did::controller::get_did_list,
            endpoint::did::controller::post_did,
            endpoint::did::controller::update_did,

            endpoint::key::controller::get_key,
            endpoint::key::controller::get_key_list,
            endpoint::key::controller::post_key,

            endpoint::proof_schema::controller::post_proof_schema,
            endpoint::proof_schema::controller::get_proof_schemas,
            endpoint::proof_schema::controller::get_proof_schema_detail,
            endpoint::proof_schema::controller::delete_proof_schema,

            endpoint::proof::controller::get_proof_details,
            endpoint::proof::controller::get_proofs,
            endpoint::proof::controller::post_proof,
            endpoint::proof::controller::share_proof,
            endpoint::proof::controller::get_proof_presentation_definition,

            endpoint::ssi::controller::ssi_verifier_connect,
            endpoint::ssi::controller::ssi_verifier_submit_proof,
            endpoint::ssi::controller::ssi_verifier_reject_proof,
            endpoint::ssi::controller::ssi_issuer_connect,
            endpoint::ssi::controller::ssi_issuer_submit,
            endpoint::ssi::controller::get_revocation_list_by_id,
            endpoint::ssi::controller::oidc_get_issuer_metadata,
            endpoint::ssi::controller::oidc_service_discovery,
            endpoint::ssi::controller::oidc_create_token,
            endpoint::ssi::controller::oidc_create_credential,
            endpoint::ssi::controller::oidc_verifier_direct_post,

            endpoint::interaction::controller::handle_invitation,
            endpoint::interaction::controller::issuance_submit,
            endpoint::interaction::controller::issuance_reject,
            endpoint::interaction::controller::presentation_submit,
            endpoint::interaction::controller::presentation_reject,

            endpoint::misc::get_build_info,
        ),
        components(
            schemas(
                endpoint::config::dto::ConfigRestDTO,

                endpoint::organisation::dto::CreateOrganisationRequestRestDTO,
                endpoint::organisation::dto::CreateOrganisationResponseRestDTO,
                endpoint::organisation::dto::GetOrganisationDetailsResponseRestDTO,

                endpoint::credential::dto::CreateCredentialRequestRestDTO,
                endpoint::credential::dto::CredentialDetailClaimResponseRestDTO,
                endpoint::credential::dto::CredentialListItemResponseRestDTO,
                endpoint::credential::dto::CredentialRequestClaimRestDTO,
                endpoint::credential::dto::GetCredentialResponseRestDTO,
                endpoint::credential::dto::CredentialDetailSchemaResponseRestDTO,
                endpoint::credential::dto::CredentialRevocationCheckRequestRestDTO,
                endpoint::credential::dto::CredentialRevocationCheckResponseRestDTO,
                endpoint::credential::dto::CredentialStateRestEnum,

                endpoint::credential_schema::dto::CreateCredentialSchemaRequestRestDTO,
                endpoint::credential_schema::dto::CredentialClaimSchemaRequestRestDTO,
                endpoint::credential_schema::dto::CredentialClaimSchemaResponseRestDTO,
                endpoint::credential_schema::dto::CredentialSchemaResponseRestDTO,
                endpoint::credential_schema::dto::CredentialSchemaListItemResponseRestDTO,

                endpoint::did::dto::CreateDidRequestRestDTO,
                endpoint::did::dto::CreateDidRequestKeysRestDTO,
                endpoint::did::dto::DidPatchRequestRestDTO,
                endpoint::did::dto::DidResponseRestDTO,
                endpoint::did::dto::DidResponseKeysRestDTO,
                endpoint::did::dto::DidListItemResponseRestDTO,
                endpoint::did::dto::DidType,

                endpoint::key::dto::KeyRequestRestDTO,
                endpoint::key::dto::KeyResponseRestDTO,
                endpoint::key::dto::KeyListItemResponseRestDTO,

                endpoint::proof::dto::ProofStateRestEnum,
                endpoint::proof::dto::CreateProofRequestRestDTO,
                endpoint::proof::dto::ProofListItemResponseRestDTO,
                endpoint::proof::dto::ProofDetailResponseRestDTO,
                endpoint::proof::dto::ProofClaimRestDTO,
                endpoint::proof::dto::PresentationDefinitionResponseRestDTO,
                endpoint::proof::dto::PresentationDefinitionRequestGroupResponseRestDTO,
                endpoint::proof::dto::PresentationDefinitionRuleRestDTO,
                endpoint::proof::dto::PresentationDefinitionRequestedCredentialResponseRestDTO,
                endpoint::proof::dto::PresentationDefinitionFieldRestDTO,
                endpoint::proof::dto::PresentationDefinitionRuleRestDTO,
                endpoint::proof::dto::PresentationDefinitionRuleTypeRestEnum,

                endpoint::proof_schema::dto::CreateProofSchemaRequestRestDTO,
                endpoint::proof_schema::dto::ClaimProofSchemaRequestRestDTO,
                endpoint::proof_schema::dto::SortableProofSchemaColumnRestEnum,
                endpoint::proof_schema::dto::GetProofSchemaListItemResponseRestDTO,
                endpoint::proof_schema::dto::GetProofSchemaResponseRestDTO,
                endpoint::proof_schema::dto::ProofClaimSchemaResponseRestDTO,

                endpoint::ssi::dto::ConnectRequestRestDTO,
                endpoint::ssi::dto::ConnectVerifierResponseRestDTO,
                endpoint::ssi::dto::ProofRequestClaimRestDTO,
                endpoint::ssi::dto::ConnectIssuerResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIIssuerMetadataResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIIssuerMetadataCredentialSupportedResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIIssuerMetadataCredentialDefinitionResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIIssuerMetadataCredentialSupportedDisplayRestDTO,
                endpoint::ssi::dto::OpenID4VCICredentialDefinitionRequestRestDTO,
                endpoint::ssi::dto::OpenID4VCICredentialRequestRestDTO,
                endpoint::ssi::dto::OpenID4VCIProofRequestRestDTO,
                endpoint::ssi::dto::OpenID4VCICredentialResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIDiscoveryResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCITokenResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIErrorResponseRestDTO,
                endpoint::ssi::dto::OpenID4VCIErrorRestEnum,
                endpoint::ssi::dto::OpenID4VCITokenRequestRestDTO,
                endpoint::ssi::dto::OpenID4VPDirectPostRequestRestDTO,
                endpoint::ssi::dto::OpenID4VPDirectPostResponseRestDTO,
                endpoint::ssi::dto::NestedPresentationSubmissionDescriptorRestDTO,
                endpoint::ssi::dto::PresentationSubmissionMappingRestDTO,
                endpoint::ssi::dto::PresentationSubmissionDescriptorRestDTO,
                endpoint::ssi::dto::DurationSecondsRest,

                endpoint::interaction::dto::HandleInvitationRequestRestDTO,
                endpoint::interaction::dto::HandleInvitationResponseRestDTO,
                endpoint::interaction::dto::IssuanceSubmitRequestRestDTO,
                endpoint::interaction::dto::IssuanceRejectRequestRestDTO,
                endpoint::interaction::dto::PresentationRejectRequestRestDTO,
                endpoint::interaction::dto::PresentationSubmitRequestRestDTO,
                endpoint::interaction::dto::PresentationSubmitCredentialRequestRestDTO,

                dto::common::GetDidsResponseRestDTO,
                dto::common::GetProofSchemaListResponseRestDTO,

                dto::common::GetCredentialsResponseDTO,
                dto::common::GetCredentialSchemaResponseDTO,
                dto::common::GetProofsResponseRestDTO,
                dto::common::GetKeyListResponseRestDTO,

                dto::common::EntityResponseRestDTO,
                dto::common::EntityShareResponseRestDTO,
                dto::common::SortDirection,

                shared_types::DidId,
                shared_types::DidValue,
            )
        ),
        tags(
            (name = "credential_schema_management", description = "Credential schema management"),
            (name = "proof_schema_management", description = "Proof schema management"),
            (name = "ssi", description = "SSI"),
            (name = "other", description = "Other utility endpoints"),
            (name = "interaction", description = "Holder functionality"),
            (name = "key", description = "Key management"),
        ),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    struct SecurityAddon;

    impl Modify for SecurityAddon {
        fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
            let components = openapi.components.as_mut().expect("OpenAPI Components");
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("BFF access token"))
                        .build(),
                ),
            );
            components.add_security_scheme(
                "OpenID4VCI",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some("OpenID4VCI token"))
                        .build(),
                ),
            );
        }
    }

    let mut docs = ApiDoc::openapi();
    docs.info.version = app_version();

    docs
}

fn app_version() -> String {
    build_info::APP_VERSION
        .map(Into::into)
        .unwrap_or_else(|| format!("{}-{}", build_info::PKG_VERSION, build_info::SHORT_COMMIT))
}
