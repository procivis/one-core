#![cfg_attr(feature = "strict", deny(warnings))]

use std::any::Any;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{middleware, Extension, Router};
use one_core::OneCore;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, info_span, Span};
use utoipa_swagger_ui::SwaggerUi;

use crate::dto::response::ErrorResponse;
use crate::endpoint::{
    config, credential, credential_schema, did, did_resolver, history, interaction, jsonld, key,
    misc, organisation, proof, proof_schema, ssi, task, trust_anchor, trust_entity, vc_api,
};
use crate::middleware::get_http_request_context;
use crate::openapi::gen_openapi_documentation;
use crate::ServerConfig;

pub(crate) struct InternalAppState {
    pub core: OneCore,
    pub config: Arc<ServerConfig>,
}

pub(crate) type AppState = Arc<InternalAppState>;

pub async fn start_server(listener: TcpListener, config: ServerConfig, core: OneCore) {
    listener.set_nonblocking(true).unwrap();

    let config = Arc::new(config);
    let state: AppState = Arc::new(InternalAppState {
        core,
        config: config.to_owned(),
    });

    let addr = listener.local_addr().expect("Invalid TCP listener");
    info!("Starting server at http://{addr}");

    let router = router(state, config);

    axum::serve(
        tokio::net::TcpListener::from_std(listener)
            .expect("failed to convert to tokio TcpListener"),
        router.into_make_service(),
    )
    .await
    .expect("Failed to start axum server");
}

fn router(state: AppState, config: Arc<ServerConfig>) -> Router {
    let openapi_documentation = gen_openapi_documentation();

    let protected = Router::new()
        .route("/api/config/v1", get(config::controller::get_config))
        .route(
            "/api/credential/v1",
            get(credential::controller::get_credential_list)
                .post(credential::controller::post_credential)
                .layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/api/credential/v1/:id",
            delete(credential::controller::delete_credential)
                .get(credential::controller::get_credential),
        )
        .route(
            "/api/credential/v1/:id/reactivate",
            post(credential::controller::reactivate_credential),
        )
        .route(
            "/api/credential/v1/:id/revoke",
            post(credential::controller::revoke_credential),
        )
        .route(
            "/api/credential/v1/:id/suspend",
            post(credential::controller::suspend_credential),
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
            "/api/credential-schema/v1/import",
            post(credential_schema::controller::import_credential_schema),
        )
        .route(
            "/api/credential-schema/v1/:id/share",
            post(credential_schema::controller::share_credential_schema),
        )
        .route(
            "/api/proof-schema/v1/:id",
            delete(proof_schema::controller::delete_proof_schema)
                .get(proof_schema::controller::get_proof_schema_detail),
        )
        .route(
            "/api/proof-schema/v1/:id/share",
            post(proof_schema::controller::share_proof_schema),
        )
        .route(
            "/api/proof-schema/v1/import",
            post(proof_schema::controller::import_proof_schema),
        )
        .route(
            "/api/history/v1",
            get(history::controller::get_history_list),
        )
        .route(
            "/api/history/v1/:id",
            get(history::controller::get_history_entry),
        )
        .route("/api/key/v1/:id", get(key::controller::get_key))
        .route(
            "/api/key/v1/:id/check-certificate",
            post(key::controller::check_certificate),
        )
        .route(
            "/api/key/v1/:id/generate-csr",
            post(key::controller::generate_csr),
        )
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
            "/api/proof-request/v1/:id/retract",
            post(proof::controller::retract_proof),
        )
        .route(
            "/api/proof-request/v1/:id/claims",
            delete(proof::controller::delete_proof_claims),
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
            "/api/did-resolver/v1/:didvalue",
            get(did_resolver::controller::resolve_did),
        )
        .route(
            "/api/interaction/v1/handle-invitation",
            post(interaction::controller::handle_invitation),
        )
        .route(
            "/api/interaction/v1/issuance-accept",
            post(interaction::controller::issuance_accept),
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
            "/api/interaction/v1/propose-proof",
            post(interaction::controller::propose_proof),
        )
        .route(
            "/api/interaction/v1/presentation-reject",
            post(interaction::controller::presentation_reject),
        )
        .route("/api/task/v1/run", post(task::controller::post_task))
        .route(
            "/api/trust-anchor/v1",
            post(trust_anchor::controller::create_trust_anchor),
        )
        .route(
            "/api/trust-anchor/v1/:id",
            get(trust_anchor::controller::get_trust_anchor),
        )
        .route(
            "/api/trust-anchor/v1",
            get(trust_anchor::controller::get_trust_anchors),
        )
        .route(
            "/api/trust-anchor/v1/:id",
            delete(trust_anchor::controller::delete_trust_anchor),
        )
        .route(
            "/api/trust-entity/v1",
            post(trust_entity::controller::create_trust_entity)
                .get(trust_entity::controller::get_trust_entities),
        )
        .route(
            "/api/trust-entity/v1/:id",
            delete(trust_entity::controller::delete_trust_entity)
                .get(trust_entity::controller::get_trust_entity_details),
        )
        .route(
            "/api/jsonld-context/v1",
            get(jsonld::controller::resolve_jsonld_context),
        )
        .layer(middleware::from_fn(crate::middleware::bearer_check));

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
            "/ssi/oidc-issuer/v1/:credential_schema_id/offer/:credential_id",
            get(ssi::controller::oidc_get_credential_offer),
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
            post(ssi::controller::oidc_verifier_direct_post).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/ssi/oidc-verifier/v1/:id/presentation-definition",
            get(ssi::controller::oidc_verifier_presentation_definition),
        )
        .route(
            "/ssi/oidc-verifier/v1/:id/client-metadata",
            get(ssi::controller::oidc_client_metadata),
        )
        .route(
            "/ssi/revocation/v1/list/:id",
            get(ssi::controller::get_revocation_list_by_id),
        )
        .route(
            "/ssi/revocation/v1/lvvc/:id",
            get(ssi::controller::get_lvvc_by_credential_id),
        )
        .route(
            "/ssi/did-web/v1/:id/did.json",
            get(ssi::controller::get_did_web_document),
        )
        .route(
            "/ssi/context/v1/:id",
            get(ssi::controller::get_json_ld_context),
        )
        .route(
            "/ssi/schema/v1/:id",
            get(ssi::controller::ssi_get_credential_schema),
        )
        .route(
            "/ssi/proof-schema/v1/:id",
            get(ssi::controller::ssi_get_proof_schema),
        )
        .route(
            "/ssi/trust/v1/:trustAnchorId",
            get(ssi::controller::ssi_get_trust_list),
        );

    let technical_endpoints = Router::new()
        .route("/build-info", get(misc::get_build_info))
        .route("/health", get(misc::health_check))
        .route("/metrics", get(misc::get_metrics))
        .route(
            "/api-docs/openapi.yaml",
            get(misc::get_openapi_yaml(openapi_documentation.clone())),
        );

    let router = {
        if config.insecure_vc_api_endpoints_enabled {
            let interop_test_endpoints = Router::new()
                .route(
                    "/vc-api/credentials/issue",
                    post(vc_api::controller::issue_credential),
                )
                .route(
                    "/vc-api/credentials/verify",
                    post(vc_api::controller::verify_credential),
                )
                .route(
                    "/vc-api/presentations/verify",
                    post(vc_api::controller::verify_presentation),
                )
                .route(
                    "/vc-api/identifiers/:identifier",
                    get(vc_api::controller::resolve_identifier),
                );

            Router::new().merge(interop_test_endpoints)
        } else {
            Router::new()
        }
    };

    router
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
                .on_failure(|_, _, _: &_| {}) // override default on_failure handler
                .on_response(|response: &Response<_>, _: Duration, _span: &Span| {
                    tracing::debug!("SERVICE CALL END {}", response.status())
                }),
        )
        .layer(middleware::from_fn(crate::middleware::sentry_layer))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi_documentation))
        .layer(middleware::from_fn(crate::middleware::metrics_counter))
        .merge(technical_endpoints)
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(Extension(config))
        .with_state(state)
}

fn handle_panic(err: Box<dyn Any + Send + 'static>) -> Response<Body> {
    let message = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic message".to_string()
    };

    tracing::error!("PANIC occurred in request: {message}");

    ErrorResponse::for_panic(message).into_response()
}
