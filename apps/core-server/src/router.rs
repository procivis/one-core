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
use axum::{Extension, Router, middleware};
use one_core::OneCore;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::{Span, info, info_span, warn};
use utoipa_swagger_ui::SwaggerUi;

use crate::ServerConfig;
use crate::dto::response::ErrorResponse;
use crate::endpoint::{
    cache, config, credential, credential_schema, did, did_resolver, history, identifier,
    interaction, jsonld, key, misc, organisation, proof, proof_schema, ssi, task, trust_anchor,
    trust_entity, vc_api,
};
use crate::middleware::get_http_request_context;
use crate::openapi::gen_openapi_documentation;

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
    let mut openapi_documentation = if config.enable_open_api {
        Some(gen_openapi_documentation(config.clone()))
    } else {
        None
    };

    if !config.enable_management_endpoints && !config.enable_external_endpoints {
        warn!("Management APIs and External APIs disabled.");
    }

    let mut openapi_paths = openapi_documentation.as_mut().map(|d| &mut d.paths.paths);

    let protected = if config.enable_management_endpoints {
        Router::new()
            .route("/api/cache/v1", delete(cache::controller::prune_cache))
            .route("/api/config/v1", get(config::controller::get_config))
            .route(
                "/api/credential/v1",
                get(credential::controller::get_credential_list)
                    .post(credential::controller::post_credential)
                    .layer(DefaultBodyLimit::disable()),
            )
            .route(
                "/api/credential/v1/{id}",
                delete(credential::controller::delete_credential)
                    .get(credential::controller::get_credential),
            )
            .route(
                "/api/credential/v1/{id}/reactivate",
                post(credential::controller::reactivate_credential),
            )
            .route(
                "/api/credential/v1/{id}/revoke",
                post(credential::controller::revoke_credential),
            )
            .route(
                "/api/credential/v1/{id}/suspend",
                post(credential::controller::suspend_credential),
            )
            .route(
                "/api/credential/v1/{id}/share",
                post(credential::controller::share_credential),
            )
            .route(
                "/api/credential/v1/revocation-check",
                post(credential::controller::revocation_check),
            )
            .route(
                "/api/proof-request/v1/{id}/share",
                post(proof::controller::share_proof),
            )
            .route(
                "/api/credential-schema/v1/{id}",
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
                "/api/credential-schema/v1/{id}/share",
                post(credential_schema::controller::share_credential_schema),
            )
            .route(
                "/api/proof-schema/v1/{id}",
                delete(proof_schema::controller::delete_proof_schema)
                    .get(proof_schema::controller::get_proof_schema_detail),
            )
            .route(
                "/api/proof-schema/v1/{id}/share",
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
                "/api/history/v1/{id}",
                get(history::controller::get_history_entry),
            )
            .route("/api/key/v1/{id}", get(key::controller::get_key))
            .route(
                "/api/key/v1/{id}/check-certificate",
                post(key::controller::check_certificate),
            )
            .route(
                "/api/key/v1/{id}/generate-csr",
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
                "/api/proof-request/v1/{id}",
                get(proof::controller::get_proof_details).delete(proof::controller::delete_proof),
            )
            .route(
                "/api/proof-request/v1/{id}/presentation-definition",
                get(proof::controller::get_proof_presentation_definition),
            )
            .route(
                "/api/proof-request/v1/{id}/claims",
                delete(proof::controller::delete_proof_claims),
            )
            .route(
                "/api/organisation/v1",
                get(organisation::controller::get_organisations)
                    .post(organisation::controller::post_organisation),
            )
            .route(
                "/api/organisation/v1/{id}",
                get(organisation::controller::get_organisation)
                    .put(organisation::controller::put_organisation),
            )
            .route("/api/did/v1/{id}", get(did::controller::get_did))
            .route(
                "/api/did/v1/{id}/trust-entity",
                get(did::controller::get_did_trust_entity),
            )
            .route("/api/did/v1/{id}", patch(did::controller::update_did))
            .route("/api/did/v1", get(did::controller::get_did_list))
            .route("/api/did/v1", post(did::controller::post_did))
            .route(
                "/api/identifier/v1",
                get(identifier::controller::get_identifier_list)
                    .post(identifier::controller::post_identifier),
            )
            .route(
                "/api/identifier/v1/{id}",
                get(identifier::controller::get_identifier)
                    .delete(identifier::controller::delete_identifier),
            )
            .route(
                "/api/did-resolver/v1/{didvalue}",
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
                "/api/trust-anchor/v1/{id}",
                get(trust_anchor::controller::get_trust_anchor),
            )
            .route(
                "/api/trust-anchor/v1",
                get(trust_anchor::controller::get_trust_anchors),
            )
            .route(
                "/api/trust-anchor/v1/{id}",
                delete(trust_anchor::controller::delete_trust_anchor),
            )
            .route(
                "/api/trust-entity/v1",
                post(trust_entity::controller::create_trust_entity)
                    .get(trust_entity::controller::get_trust_entities),
            )
            .route(
                "/api/trust-entity/v1/{id}",
                patch(trust_entity::controller::update_trust_entity)
                    .get(trust_entity::controller::get_trust_entity_details),
            )
            .route(
                "/api/trust-entity/remote/v1",
                post(trust_entity::controller::create_remote_trust_entity),
            )
            .route(
                "/api/trust-entity/remote/v1/{did_id}",
                get(trust_entity::controller::get_remote_trust_entity)
                    .patch(trust_entity::controller::update_remote_trust_entity),
            )
            .route(
                "/api/jsonld-context/v1",
                get(jsonld::controller::resolve_jsonld_context),
            )
            .layer(middleware::from_fn(crate::middleware::bearer_check))
    } else {
        if let Some(paths) = openapi_paths.as_mut() {
            paths.shift_remove("/api");
        };
        Router::new()
    };

    let unprotected = if config.enable_external_endpoints {
        Router::new()
            .route(
                "/ssi/openid4vci/draft-13/{id}/.well-known/openid-credential-issuer",
                get(ssi::issuance::draft13::controller::oid4vci_draft13_get_issuer_metadata),
            )
            .route(
                "/ssi/openid4vci/draft-13/{id}/.well-known/openid-configuration",
                get(ssi::issuance::draft13::controller::oid4vci_draft13_service_discovery),
            )
            .route(
                "/ssi/openid4vci/draft-13/{credential_schema_id}/offer/{credential_id}",
                get(ssi::issuance::draft13::controller::oid4vci_draft13_get_credential_offer),
            )
            .route(
                "/ssi/openid4vci/draft-13/{id}/token",
                post(ssi::issuance::draft13::controller::oid4vci_draft13_create_token),
            )
            .route(
                "/ssi/openid4vci/draft-13/{id}/credential",
                post(ssi::issuance::draft13::controller::oid4vci_draft13_create_credential),
            )
            .route(
                "/ssi/openid4vci/draft-13-swiyu/{id}/.well-known/openid-credential-issuer",
                get(ssi::issuance::draft13_swiyu::controller::oid4vci_draft13_swiyu_get_issuer_metadata),
            )
            .route(
                "/ssi/openid4vci/draft-13-swiyu/{id}/.well-known/openid-configuration",
                get(ssi::issuance::draft13_swiyu::controller::oid4vci_draft13_swiyu_service_discovery),
            )
            .route(
                "/ssi/openid4vci/draft-13-swiyu/{credential_schema_id}/offer/{credential_id}",
                get(ssi::issuance::draft13_swiyu::controller::oid4vci_draft13_swiyu_get_credential_offer),
            )
            .route(
                "/ssi/openid4vci/draft-13-swiyu/{id}/token",
                post(ssi::issuance::draft13_swiyu::controller::oid4vci_draft13_swiyu_create_token),
            )
            .route(
                "/ssi/openid4vci/draft-13-swiyu/{id}/credential",
                post(ssi::issuance::draft13_swiyu::controller::oid4vci_draft13_swiyu_create_credential),
            )
            .route(
                "/ssi/openid4vp/draft-20/response",
                post(ssi::verification::draft20::controller::oid4vp_draft20_direct_post)
                    .layer(DefaultBodyLimit::disable()),
            )
            .route(
                "/ssi/openid4vp/draft-20/{id}/presentation-definition",
                get(ssi::verification::draft20::controller::oid4vp_draft20_presentation_definition),
            )
            .route(
                "/ssi/openid4vp/draft-20/{id}/client-metadata",
                get(ssi::verification::draft20::controller::oid4vp_draft20_client_metadata),
            )
            .route(
                "/ssi/openid4vp/draft-20/{id}/client-request",
                get(ssi::verification::draft20::controller::oid4vp_draft20_client_request),
            )
            .route(
                "/ssi/openid4vp/draft-25/response",
                post(ssi::verification::draft25::controller::oid4vp_draft25_direct_post)
                    .layer(DefaultBodyLimit::disable()),
            )
            .route(
                "/ssi/openid4vp/draft-25/{id}/presentation-definition",
                get(ssi::verification::draft25::controller::oid4vp_draft25_presentation_definition),
            )
            .route(
                "/ssi/openid4vp/draft-25/{id}/client-metadata",
                get(ssi::verification::draft25::controller::oid4vp_draft25_client_metadata),
            )
            .route(
                "/ssi/openid4vp/draft-25/{id}/client-request",
                get(ssi::verification::draft25::controller::oid4vp_draft25_client_request),
            )
            .route(
                "/ssi/revocation/v1/list/{id}",
                get(ssi::controller::get_revocation_list_by_id),
            )
            .route(
                "/ssi/revocation/v1/lvvc/{id}",
                get(ssi::controller::get_lvvc_by_credential_id),
            )
            .route(
                "/ssi/did-web/v1/{id}/did.json",
                get(ssi::controller::get_did_web_document),
            )
            .route(
                "/ssi/did-webvh/v1/{id}/did.jsonl",
                get(ssi::controller::get_did_webvh_log),
            )
            .route(
                "/ssi/context/v1/{id}",
                get(ssi::controller::get_json_ld_context),
            )
            .route(
                "/ssi/schema/v1/{id}",
                get(ssi::controller::ssi_get_credential_schema),
            )
            .route(
                "/ssi/proof-schema/v1/{id}",
                get(ssi::controller::ssi_get_proof_schema),
            )
            .route(
                "/ssi/trust/v1/{trustAnchorId}",
                get(ssi::controller::ssi_get_trust_list),
            )
            .route(
                "/ssi/trust-entity/v1/{didValue}",
                get(ssi::controller::ssi_get_trust_entity)
                    .patch(ssi::controller::ssi_patch_trust_entity),
            )
            .route(
                "/ssi/trust-entity/v1",
                post(ssi::controller::ssi_post_trust_entity),
            )
            .route(
                "/ssi/vct/v1/{organisationId}/{vctType}",
                get(ssi::controller::ssi_get_sd_jwt_vc_type_metadata),
            )
    } else {
        if let Some(paths) = openapi_paths.as_mut() {
            paths.shift_remove("/ssi");
        };
        Router::new()
    };

    let metrics_endpoints = if config.enable_metrics {
        Router::new().route("/metrics", get(misc::get_metrics))
    } else {
        if let Some(paths) = openapi_paths.as_mut() {
            paths.shift_remove("/metrics");
        };
        Router::new()
    };

    let server_info_endpoints = if config.enable_server_info {
        Router::new()
            .route("/build-info", get(misc::get_build_info))
            .route("/health", get(misc::health_check))
    } else {
        if let Some(paths) = openapi_paths.as_mut() {
            paths.shift_remove("/build-info");
            paths.shift_remove("/health");
        };
        Router::new()
    };

    let openapi_endpoints = if let Some(openapi_documentation) = openapi_documentation {
        Router::new()
            .route(
                "/api-docs/openapi.yaml",
                get(misc::get_openapi_yaml(&openapi_documentation)),
            )
            .merge(
                SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi_documentation),
            )
    } else {
        Router::new()
    };

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
                    "/vc-api/identifiers/{identifier}",
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
        .layer(middleware::from_fn(crate::middleware::metrics_counter))
        .merge(metrics_endpoints)
        .merge(server_info_endpoints)
        .merge(openapi_endpoints)
        .layer(CatchPanicLayer::custom(handle_panic))
        .layer(Extension(config))
        .layer(middleware::from_fn(
            crate::middleware::add_disable_cache_headers,
        ))
        .layer(middleware::from_fn(
            crate::middleware::add_x_content_type_options_no_sniff_header,
        ))
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
