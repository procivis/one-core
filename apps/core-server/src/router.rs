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
use indexmap::IndexMap;
use one_core::OneCore;
use one_core::proto::session_provider::Session;
use sql_data_provider::DbConn;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::Span;
use url::Url;
use utoipa::openapi::PathItem;
use utoipa_swagger_ui::SwaggerUi;

use crate::ServerConfig;
use crate::authentication::{Authentication, authentication};
use crate::dto::response::ErrorResponse;
use crate::endpoint::trust_collection::controller::{
    delete_trust_list_subscription, get_trust_list_subscription_entries,
    post_trust_list_subscription,
};
use crate::endpoint::{
    cache, certificate, config, credential, credential_schema, did, did_resolver, history,
    identifier, instance, interaction, jsonld, key, managed_instance, misc, organisation, proof,
    proof_schema, qes, signature, ssi, statistics, system, task, trust_collection,
    trust_list_publication, vc_api,
};
use crate::middleware::get_http_request_context;
use crate::openapi::gen_openapi_documentation;

pub(crate) struct InternalAppState {
    pub core: OneCore,
    pub config: Arc<ServerConfig>,
    pub db: DbConn,
}

pub(crate) type AppState = Arc<InternalAppState>;

#[expect(clippy::expect_used)]
#[expect(clippy::unwrap_used)]
pub async fn start_server(listener: TcpListener, config: ServerConfig, core: OneCore, db: DbConn) {
    listener.set_nonblocking(true).unwrap();

    let config = Arc::new(config);
    let state: AppState = Arc::new(InternalAppState {
        core,
        config: config.to_owned(),
        db,
    });

    let addr = listener.local_addr().expect("Invalid TCP listener");
    tracing::info!("Starting server at http://{addr}");

    let authentication = authentication(&config)
        .await
        .expect("Failed to initialize authentication");
    let router = router(state, config, authentication);

    axum::serve(
        tokio::net::TcpListener::from_std(listener)
            .expect("failed to convert to tokio TcpListener"),
        router.into_make_service(),
    )
    .await
    .expect("Failed to start axum server");
}

fn router(state: AppState, config: Arc<ServerConfig>, authentication: Authentication) -> Router {
    let mut openapi_documentation = config.enable_open_api.then_some(gen_openapi_documentation(
        config.clone(),
        state.core.config.clone(),
    ));

    let mut openapi_paths = openapi_documentation.as_mut().map(|d| &mut d.paths.paths);

    if !config.enable_management_endpoints && !config.enable_external_endpoints {
        tracing::warn!("Management APIs and External APIs disabled.");
    }

    let management_endpoints = get_management_endpoints(&config, &mut openapi_paths);

    let external_endpoints = get_external_endpoints(&config, &mut openapi_paths);

    let system_endpoints = get_system_endpoints(&config, &mut openapi_paths);

    let openapi_endpoints = if let Some(openapi_documentation) = openapi_documentation {
        Router::new()
            .route(
                "/api-docs/openapi.yaml",
                get(misc::get_openapi_yaml(&openapi_documentation)),
            )
            .merge({
                let json_path = "/api-docs/openapi.json";
                let config = if let Ok(base_url) = Url::try_from(config.core_base_url.as_str()) {
                    match base_url.path() {
                        "/" => None,
                        path => Some(utoipa_swagger_ui::Config::from(format!(
                            "{path}{json_path}"
                        ))),
                    }
                } else {
                    None
                };

                SwaggerUi::new("/swagger-ui")
                    .url(json_path, openapi_documentation)
                    .config(config.unwrap_or_default())
            })
            .layer(middleware::from_fn(
                crate::openapi::swagger_plugin::adapted_swagger_index,
            ))
    } else {
        Router::new()
    };

    let vcapi_endpoints = if config.insecure_vc_api_endpoints_enabled {
        Router::new()
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
            )
    } else {
        Router::new()
    };

    let hide_error_response_cause = config.hide_error_response_cause;

    let mut router = management_endpoints
        .merge(external_endpoints)
        .merge(vcapi_endpoints)
        .layer(middleware::from_fn(crate::middleware::sentry_layer))
        .layer(middleware::from_fn(crate::middleware::metrics_counter))
        .merge(openapi_endpoints)
        .merge(system_endpoints)
        .layer(CatchPanicLayer::custom(move |err| {
            handle_panic(err, hide_error_response_cause)
        }))
        .layer(Extension(config))
        .layer(middleware::from_fn(
            crate::middleware::add_disable_cache_headers,
        ))
        .layer(middleware::from_fn(
            crate::middleware::add_x_content_type_options_no_sniff_header,
        ));

    if tracing::enabled!(target: "core_server::middleware", tracing::Level::TRACE) {
        router = router.layer(middleware::from_fn(
            crate::middleware::log_request_and_response,
        ));
    }

    router
        // Only now log messages from authorization extraction once the request span is set up
        .layer(middleware::from_fn(crate::middleware::log_authz_warning))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let context = get_http_request_context(request);
                    let session = request.extensions().get::<Session>();
                    tracing::error_span!(
                        "http_request",
                        method = context.method,
                        path = context.path,
                        service = "one-core",
                        requestId = context.request_id.as_ref(),
                        sessionId = context.session_id, // Derived from x-session-id header,
                        organisation = session
                            .and_then(|s| s.organisation_id)
                            .map(|o| o.to_string()),
                        user = session.map(|s| s.user_id.clone()),
                        actor = session.and_then(|s| s.actor.clone())
                    )
                })
                .on_request(|request: &Request<_>, _span: &Span| {
                    tracing::info!(
                        "SERVICE CALL START {} {}",
                        request.method(),
                        request.uri().path()
                    )
                })
                .on_failure(|_, _, _: &_| {}) // override default on_failure handler
                .on_response(|response: &Response<_>, duration: Duration, _: &_| {
                    tracing::info!(
                        "SERVICE CALL END {} ({} ms)",
                        response.status(),
                        duration.as_millis()
                    );
                }),
        )
        // Eagerly extract and validate authorization, so there is accurate user / session information for logging
        .layer(middleware::from_fn(crate::middleware::session_init))
        .layer(Extension(authentication))
        .with_state(state)
}

#[expect(deprecated)]
fn get_management_endpoints(
    config: &ServerConfig,
    openapi_paths: &mut Option<&mut IndexMap<String, PathItem>>,
) -> Router<AppState> {
    if config.enable_management_endpoints {
        let large_request_body_limit = config.max_large_request_body_bytes;

        let mut router = Router::new()
            .route("/api/cache/v1", delete(cache::controller::prune_cache))
            .route("/api/config/v1", get(config::controller::get_config))
            .route(
                "/api/credential/v1",
                get(credential::controller::get_credential_list)
                    .post(credential::controller::post_credential)
                    .layer(DefaultBodyLimit::max(large_request_body_limit)),
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
                "/api/credential/v1/{id}/state",
                patch(credential::controller::patch_credential_state),
            )
            .route(
                "/api/credential/v1/{id}/share",
                post(credential::controller::share_credential),
            )
            .route(
                "/api/credential/v1/{id}/trust-detail",
                get(credential::controller::get_credential_trust_detail),
            )
            .route(
                "/api/credential/v1/revocation-check",
                post(credential::controller::credential_revocation_check),
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
                "/api/credential-schema/v2/{id}",
                get(credential_schema::controller::get_credential_schema_v2),
            )
            .route(
                "/api/credential-schema/v2/{id}/share",
                post(credential_schema::controller::share_credential_schema_v2),
            )
            .route(
                "/api/credential-schema/v2",
                get(credential_schema::controller::get_credential_schema_list_v2)
                    .post(credential_schema::controller::post_credential_schema_v2),
            )
            .route(
                "/api/credential-schema/v2/import",
                post(credential_schema::controller::import_credential_schema_v2),
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
            .route("/api/history/v1", {
                let mut routes = get(history::controller::get_history_list);
                if config.enable_history_create_endpoint {
                    routes = routes.post(history::controller::create_history);
                } else if let Some(paths) = openapi_paths
                    && let Some(path) = paths.get_mut("/api/history/v1")
                {
                    path.post = None;
                }
                routes
            })
            .route(
                "/api/history/v1/{id}",
                get(history::controller::get_history_entry),
            )
            .route("/api/key/v1/{id}", get(key::controller::get_key))
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
                "/api/proof-request/v2/{id}/presentation-definition",
                get(proof::controller::get_proof_presentation_definition_v2),
            )
            .route(
                "/api/proof-request/v1/{proofId}/transaction-data/{transactionDataId}",
                get(proof::controller::get_proof_transaction_data),
            )
            .route(
                "/api/proof-request/v1/{id}/claims",
                delete(proof::controller::delete_proof_claims),
            )
            .route(
                "/api/proof-request/v1/{id}/trust-detail",
                get(proof::controller::get_proof_trust_detail),
            )
            .route(
                "/api/organisation/v1",
                get(organisation::controller::get_organisations)
                    .post(organisation::controller::post_organisation),
            )
            .route(
                "/api/organisation/v1/{id}",
                get(organisation::controller::get_organisation)
                    .patch(organisation::controller::patch_organisation),
            )
            .route("/api/did/v1/{id}", get(did::controller::get_did))
            .route("/api/did/v1/{id}", patch(did::controller::update_did))
            .route("/api/did/v1", get(did::controller::get_did_list))
            .route("/api/did/v1", post(did::controller::post_did))
            .route(
                "/api/certificate/v1/{id}",
                get(certificate::controller::get_certificate),
            )
            .route(
                "/api/identifier/v1",
                get(identifier::controller::get_identifier_list)
                    .post(identifier::controller::post_identifier),
            )
            .route(
                "/api/identifier/v1/resolve-trust-entries",
                post(identifier::controller::resolve_trust_entries),
            )
            .route(
                "/api/identifier/v1/{id}",
                get(identifier::controller::get_identifier)
                    .delete(identifier::controller::delete_identifier)
                    .patch(identifier::controller::patch_identifier),
            )
            .route(
                "/api/identifier/v1/remote",
                post(identifier::controller::post_remote_identifier),
            )
            .route(
                "/api/identifier/v1/{id}/certificate",
                post(identifier::controller::post_identifier_certificates),
            )
            .route(
                "/api/identifier/v1/{identifierId}/certificate/{certificateId}",
                delete(identifier::controller::delete_identifier_certificate),
            )
            .route(
                "/api/identifier/v1/{id}/certificate-authority",
                post(identifier::controller::post_identifier_certificate_authorities),
            )
            .route(
                "/api/identifier/v1/{identifierId}/certificate-authority/{certificateAuthorityId}",
                delete(identifier::controller::delete_identifier_certificate_authority),
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
                "/api/interaction/v1/{id}/issuance-refresh",
                post(interaction::controller::issuance_refresh),
            )
            .route(
                "/api/interaction/v2/presentation-submit",
                post(interaction::controller::presentation_submit_v2),
            )
            .route(
                "/api/interaction/v1/propose-proof",
                post(interaction::controller::propose_proof),
            )
            .route(
                "/api/interaction/v1/presentation-reject",
                post(interaction::controller::presentation_reject),
            )
            .route(
                "/api/interaction/v1/initiate-issuance",
                post(interaction::controller::initiate_issuance),
            )
            .route(
                "/api/interaction/v1/continue-issuance",
                post(interaction::controller::continue_issuance),
            )
            .route("/api/task/v1/run", post(task::controller::post_task))
            .route(
                "/api/managed-instance/v1",
                get(managed_instance::controller::get_managed_instance_list),
            )
            .route(
                "/api/managed-instance/v1/{id}",
                get(managed_instance::controller::get_managed_instance_details)
                    .delete(managed_instance::controller::delete_managed_instance),
            )
            .route(
                "/api/managed-instance/v1/{id}/revoke",
                post(managed_instance::controller::revoke_managed_instance),
            )
            .route(
                "/api/jsonld-context/v1",
                get(jsonld::controller::resolve_jsonld_context),
            )
            .route(
                "/api/instance/v1/{id}",
                get(instance::controller::get_instance_details),
            )
            .route(
                "/api/instance/v1/{id}/status",
                post(instance::controller::instance_status),
            )
            .route(
                "/api/instance/v1/{id}/activate",
                post(instance::controller::activate_remote_instance),
            )
            .route(
                "/api/instance/v1",
                post(instance::controller::register_remote_instance),
            )
            .route(
                "/api/statistics/v1/dashboard",
                get(statistics::controller::organisation_statistics),
            )
            .route(
                "/api/statistics/v1/dashboard/issuer",
                get(statistics::controller::issuer_statistics),
            )
            .route(
                "/api/statistics/v1/dashboard/verifier",
                get(statistics::controller::verifier_statistics),
            )
            .route(
                "/api/statistics/v1/dashboard/system",
                get(statistics::controller::system_statistics),
            )
            .route(
                "/api/statistics/v1/dashboard/system/interaction",
                get(statistics::controller::system_interaction_statistics),
            )
            .route(
                "/api/statistics/v1/dashboard/system/management",
                get(statistics::controller::system_management_statistics),
            )
            .route(
                "/api/trust-list/v1",
                get(trust_list_publication::controller::get_trust_list_publications)
                    .post(trust_list_publication::controller::post_trust_list_publication),
            )
            .route(
                "/api/trust-list/v1/{id}",
                get(trust_list_publication::controller::get_trust_list_publication)
                    .delete(trust_list_publication::controller::delete_trust_list_publication),
            )
            .route(
                "/api/trust-list/v1/{id}/entry",
                get(trust_list_publication::controller::get_trust_list_publication_entries)
                    .post(trust_list_publication::controller::post_trust_entry),
            )
            .route(
                "/api/trust-list/v1/{list_id}/entry/{entry_id}",
                patch(trust_list_publication::controller::patch_trust_entry)
                    .delete(trust_list_publication::controller::delete_trust_entry),
            )
            .route(
                "/api/trust-collection/v1",
                get(trust_collection::controller::get_trust_collection_list)
                    .post(trust_collection::controller::post_trust_collection),
            )
            .route(
                "/api/trust-collection/v1/{id}",
                get(trust_collection::controller::get_trust_collection)
                    .delete(trust_collection::controller::delete_trust_collection),
            )
            .route(
                "/api/trust-collection/v1/{trust_collection_id}/trust-list",
                get(get_trust_list_subscription_entries).post(post_trust_list_subscription),
            )
            .route(
                "/api/trust-collection/v1/{trust_collection_id}/trust-list/{trust_list_id}",
                delete(delete_trust_list_subscription),
            );

        if config.enable_signature_endpoints {
            router = router
                .route(
                    "/api/signature/v1",
                    post(signature::controller::create_signature),
                )
                .route(
                    "/api/signature/v1/{id}/revoke",
                    post(signature::controller::revoke_signature),
                )
                .route(
                    "/api/signature/v1/revocation-check",
                    post(signature::controller::signature_revocation_check),
                );
        } else if let Some(paths) = openapi_paths {
            paths.shift_remove("/api/signature/v1");
            paths.shift_remove("/api/signature/v1/{id}/revoke");
            paths.shift_remove("/api/signature/v1/revocation-check");
        }

        if config.enable_qes_endpoints {
            router = router
                .route("/api/qes/v1/authorize", post(qes::controller::authorize))
                .route("/api/qes/v1/sign", post(qes::controller::sign));
        } else if let Some(paths) = openapi_paths {
            paths.shift_remove("/api/qes/v1/authorize");
            paths.shift_remove("/api/qes/v1/sign");
        }

        router.layer(middleware::from_fn(crate::middleware::authorization_check))
    } else {
        if let Some(paths) = openapi_paths {
            paths.shift_remove("/api");
        };
        Router::new()
    }
}

fn get_system_endpoints(
    config: &ServerConfig,
    openapi_paths: &mut Option<&mut IndexMap<String, PathItem>>,
) -> Router<AppState> {
    let mut router = Router::new();

    if config.enable_server_info {
        router = router
            .route("/system/health/liveness", get(system::controller::liveness))
            .route(
                "/system/health/readiness",
                get(system::controller::readiness),
            )
            .route(
                "/system/build-info",
                get(system::controller::get_build_info)
                    .route_layer(middleware::from_fn(crate::middleware::authorization_check)),
            );
    } else if let Some(paths) = openapi_paths {
        paths.shift_remove("/system/health/liveness");
        paths.shift_remove("/system/health/readiness");
        paths.shift_remove("/system/build-info");
    }

    if config.enable_metrics {
        router = router.route("/system/metrics", get(system::controller::get_metrics));
    } else if let Some(paths) = openapi_paths {
        paths.shift_remove("/system/metrics");
    }

    router
}

#[expect(deprecated)]
fn get_external_endpoints(
    config: &ServerConfig,
    openapi_paths: &mut Option<&mut IndexMap<String, PathItem>>,
) -> Router<AppState> {
    let large_external_request_body_limit = config.max_large_external_request_body_bytes;

    if config.enable_external_endpoints {
        Router::new()
            .route(
                "/.well-known/jwt-vc-issuer/ssi/openid4vci/{protocol_id}/{identifier_id}/{credential_schema_id}",
                get(ssi::issuance::controller::oid4vci_get_jwt_vc_issuer_metadata)
            )
            .route(
                "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0/{protocol_id}/{identifier_id}/{credential_schema_id}",
                get(ssi::issuance::final1_0::controller::oid4vci_final1_0_get_issuer_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0/{protocol_id}/{identifier_id}/{credential_schema_id}",
                get(ssi::issuance::final1_0::controller::oid4vci_final1_0_oauth_authorization_server),
            )
            .route(
                "/ssi/openid4vci/final-1.0/{credential_schema_id}/offer/{credential_id}",
                get(ssi::issuance::final1_0::controller::oid4vci_final1_0_get_credential_offer),
            )
            .route(
                "/ssi/openid4vci/final-1.0/{id}/token",
                post(ssi::issuance::final1_0::controller::oid4vci_final1_0_create_token),
            )
            .route(
                "/ssi/openid4vci/final-1.0/{id}/credential",
                post(ssi::issuance::final1_0::controller::oid4vci_final1_0_create_credential),
            )
            .route(
                "/ssi/openid4vci/final-1.0/{id}/notification",
                post(ssi::issuance::final1_0::controller::oid4vci_final1_0_credential_notification),
            ).route(
                "/ssi/openid4vci/final-1.0/{protocol_id}/nonce",
                post(ssi::issuance::final1_0::controller::oid4vci_final1_0_nonce),
            ).route(
                "/ssi/openid4vci/final-1.0/{protocol_id}/challenge",
                post(ssi::issuance::final1_0::controller::oid4vci_final1_0_oauth_attestation_challenge),
            )
            .route(
                "/.well-known/openid-credential-issuer/ssi/openid4vci/final-1.0-swiyu/{protocol_id}/{identifier_id}/{id}",
                get(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_get_issuer_metadata),
            )
            .route(
                "/.well-known/oauth-authorization-server/ssi/openid4vci/final-1.0-swiyu/{protocol_id}/{identifier_id}/{id}",
                get(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_oauth_authorization_server),
            )
            .route(
                "/ssi/openid4vci/final-1.0-swiyu/{credential_schema_id}/offer/{credential_id}",
                get(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_get_credential_offer),
            )
            .route(
                "/ssi/openid4vci/final-1.0-swiyu/{id}/token",
                post(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_create_token),
            )
            .route(
                "/ssi/openid4vci/final-1.0-swiyu/{id}/credential",
                post(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_create_credential),
            )
            .route(
                "/ssi/openid4vci/final-1.0-swiyu/{protocol_id}/nonce",
                post(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_nonce),
            )
            .route(
                "/ssi/openid4vci/final-1.0-swiyu/{protocol_id}/challenge",
                post(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_oauth_attestation_challenge),
            )
            .route(
                "/ssi/openid4vci/final-1.0-swiyu/{id}/notification",
                post(ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_credential_notification),
            )
            .route(
                "/ssi/openid4vp/final-1.0/response",
                post(ssi::verification::final1_0::controller::oid4vp_final1_0_direct_post)
                    .layer(DefaultBodyLimit::max(large_external_request_body_limit)),
            )
            .route(
                "/ssi/openid4vp/final-1.0/{id}/client-metadata",
                get(ssi::verification::final1_0::controller::oid4vp_final1_0_client_metadata),
            )
            .route(
                "/ssi/openid4vp/final-1.0/{id}/client-request",
                get(ssi::verification::final1_0::controller::oid4vp_final1_0_client_request),
            )
            .route(
                "/ssi/openid4vp/final-1.0-swiyu/{id}/client-request",
                get(ssi::verification::final1_0_swiyu::controller::oid4vp_final1_0_swiyu_client_request),
            )
            .route(
                "/ssi/openid4vp/final-1.0-swiyu/response/{id}",
                post(ssi::verification::final1_0_swiyu::controller::oid4vp_final1_0_swiyu_direct_post)
                    .layer(DefaultBodyLimit::max(large_external_request_body_limit)),
            )
            .route(
                "/ssi/revocation/v1/list/{id}",
                get(ssi::controller::get_revocation_list_by_id),
            )
            .route(
                 "/ssi/revocation/v1/crl/{id}",
                get(ssi::controller::get_crl_by_id),
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
                "/ssi/context/v1/{id}/{format}",
                get(ssi::controller::get_json_ld_context_by_format),
            )
            .route(
                "/ssi/schema/v1/{id}",
                get(ssi::controller::ssi_get_credential_schema),
            )
            .route(
                "/ssi/schema/v2/{id}",
                get(ssi::controller::ssi_get_credential_schema_v2),
            )
            .route(
                "/ssi/schema/v2/{id}/{format}",
                get(ssi::controller::ssi_get_credential_schema_by_format_v2),
            )
            .route(
                "/ssi/proof-schema/v1/{id}",
                get(ssi::controller::ssi_get_proof_schema),
            )
            .route(
                "/ssi/vct/v1/{organisationId}/{vctType}",
                get(ssi::controller::ssi_get_sd_jwt_vc_type_metadata),
            )
            .route(
                "/ssi/vct/v2/{organisationId}/{credentialSchemaId}/{format}",
                get(ssi::controller::ssi_get_sd_jwt_vc_type_metadata_v2),
            )
            .route(
                "/ssi/ca/{id}",
                get(ssi::controller::ssi_get_certificate_authority),
            )
            .route(
                "/ssi/certificate/{id}",
                get(ssi::controller::ssi_get_certificate),
            )
            .route(
                "/ssi/verifier-provider/v1/{verifierProvider}",
                get(ssi::verifier_provider::controller::get_verification_provider)
            )
            .route(
                "/ssi/wallet-unit/v1",
                post(ssi::wallet_provider::controller::register_wallet_unit)
            )
            .route(
                "/ssi/wallet-unit/v1/{id}/activate",
                post(ssi::wallet_provider::controller::activate_wallet_unit),
            )
            .route(
                "/ssi/wallet-unit/v1/{id}/issue-attestation",
                post(ssi::wallet_provider::controller::issue_wallet_unit_attestation)
            )
            .route(
                "/ssi/wallet-provider/v1/{walletProvider}",
                get(ssi::wallet_provider::controller::get_wallet_provider_metadata),
            )
            .route(
                "/ssi/instance/v1",
                post(ssi::instance::controller::register_instance)
            )
            .route(
                "/ssi/instance/v1/{id}/activate",
                post(ssi::instance::controller::activate_instance),
            )
            .route(
                "/ssi/instance/v1/{id}/issue-attestation",
                post(ssi::instance::controller::issue_instance_attestation)
            )
            .route(
                "/ssi/trust-list/v1/{id}",
                get(ssi::controller::ssi_get_trust_list_publication),
            )
            .route(
                "/ssi/trust-collection/v1/{id}",
                get(ssi::controller::ssi_get_trust_collection),
            )
    } else {
        if let Some(paths) = openapi_paths {
            paths.shift_remove("/ssi");
        };
        Router::new()
    }
}

fn handle_panic(err: Box<dyn Any + Send + 'static>, hide_cause: bool) -> Response<Body> {
    let message = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "Unknown panic cause".to_string()
    };

    tracing::error!("PANIC occurred in request: {message}");

    ErrorResponse::for_panic(message, hide_cause).into_response()
}
