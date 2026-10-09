#![cfg_attr(feature = "strict", deny(warnings))]

use std::any::Any;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::http::{Request, Response};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Router, middleware};
use one_core::OneCore;
use one_core::proto::session_provider::Session;
use sql_data_provider::DbConn;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::trace::TraceLayer;
use tracing::Span;
use url::Url;
use utoipa::openapi::OpenApi;
use utoipa_axum::router::{OpenApiRouter, UtoipaMethodRouterExt};
use utoipa_axum::routes;
use utoipa_swagger_ui::SwaggerUi;

use crate::ServerConfig;
use crate::authentication::{Authentication, authentication};
use crate::dto::response::ErrorResponse;
use crate::endpoint::{
    cache, certificate, config, credential, credential_schema, did, did_resolver, history,
    identifier, instance, interaction, jsonld, key, managed_instance, misc, organisation, proof,
    proof_schema, qes, signature, ssi, statistics, system, task, trust_collection,
    trust_list_publication, vc_api,
};
use crate::middleware::get_http_request_context;
use crate::openapi::{base_openapi, gen_openapi_documentation};

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

/// Collects the OpenAPI paths of `router` into `openapi` and returns the plain axum router.
fn collect(router: OpenApiRouter<AppState>, openapi: &mut OpenApi) -> Router<AppState> {
    let (router, api) = router.split_for_parts();
    openapi.merge(api);
    router
}

fn router(state: AppState, config: Arc<ServerConfig>, authentication: Authentication) -> Router {
    let mut openapi = base_openapi();

    if !config.enable_management_endpoints && !config.enable_external_endpoints {
        tracing::warn!("Management APIs and External APIs disabled.");
    }

    let management_endpoints = collect(get_management_endpoints(&config), &mut openapi);

    let external_endpoints = collect(get_external_endpoints(&config), &mut openapi);

    let system_endpoints = collect(get_system_endpoints(&config), &mut openapi);

    let openapi_endpoints = if config.enable_open_api {
        let openapi_documentation =
            gen_openapi_documentation(openapi, config.clone(), state.core.config.clone());
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
fn get_management_endpoints(config: &ServerConfig) -> OpenApiRouter<AppState> {
    if !config.enable_management_endpoints {
        return OpenApiRouter::default();
    }

    let large_request_body_limit = config.max_large_request_body_bytes;

    let mut router = OpenApiRouter::default()
        .routes(routes!(cache::controller::prune_cache))
        .routes(routes!(config::controller::get_config))
        .routes(
            routes!(
                credential::controller::get_credential_list,
                credential::controller::post_credential
            )
            .layer(DefaultBodyLimit::max(large_request_body_limit)),
        )
        .routes(routes!(
            credential::controller::delete_credential,
            credential::controller::get_credential
        ))
        .routes(routes!(credential::controller::reactivate_credential))
        .routes(routes!(credential::controller::revoke_credential))
        .routes(routes!(credential::controller::suspend_credential))
        .routes(routes!(credential::controller::patch_credential_state))
        .routes(routes!(credential::controller::share_credential))
        .routes(routes!(credential::controller::get_credential_trust_detail))
        .routes(routes!(credential::controller::credential_revocation_check))
        .routes(routes!(proof::controller::share_proof))
        .routes(routes!(
            credential_schema::controller::delete_credential_schema,
            credential_schema::controller::get_credential_schema
        ))
        .routes(routes!(
            credential_schema::controller::get_credential_schema_list,
            credential_schema::controller::post_credential_schema
        ))
        .routes(routes!(
            credential_schema::controller::get_credential_schema_v2
        ))
        .routes(routes!(
            credential_schema::controller::share_credential_schema_v2
        ))
        .routes(routes!(
            credential_schema::controller::get_credential_schema_list_v2,
            credential_schema::controller::post_credential_schema_v2
        ))
        .routes(routes!(
            credential_schema::controller::import_credential_schema_v2
        ))
        .routes(routes!(
            credential_schema::controller::import_credential_schema
        ))
        .routes(routes!(
            credential_schema::controller::share_credential_schema
        ))
        .routes(routes!(
            proof_schema::controller::delete_proof_schema,
            proof_schema::controller::get_proof_schema_detail
        ))
        .routes(routes!(proof_schema::controller::share_proof_schema))
        .routes(routes!(proof_schema::controller::import_proof_schema))
        .routes(if config.enable_history_create_endpoint {
            routes!(
                history::controller::get_history_list,
                history::controller::create_history
            )
        } else {
            routes!(history::controller::get_history_list)
        })
        .routes(routes!(history::controller::get_history_entry))
        .routes(routes!(key::controller::get_key))
        .routes(routes!(key::controller::generate_csr))
        .routes(routes!(
            key::controller::post_key,
            key::controller::get_key_list
        ))
        .routes(routes!(
            proof_schema::controller::get_proof_schemas,
            proof_schema::controller::post_proof_schema
        ))
        .routes(routes!(
            proof::controller::post_proof,
            proof::controller::get_proofs
        ))
        .routes(routes!(
            proof::controller::get_proof_details,
            proof::controller::delete_proof
        ))
        .routes(routes!(
            proof::controller::get_proof_presentation_definition_v2
        ))
        .routes(routes!(proof::controller::get_proof_transaction_data))
        .routes(routes!(proof::controller::delete_proof_claims))
        .routes(routes!(proof::controller::get_proof_trust_detail))
        .routes(routes!(
            organisation::controller::get_organisations,
            organisation::controller::post_organisation
        ))
        .routes(routes!(
            organisation::controller::get_organisation,
            organisation::controller::patch_organisation
        ))
        .routes(routes!(
            did::controller::get_did,
            did::controller::update_did
        ))
        .routes(routes!(
            did::controller::get_did_list,
            did::controller::post_did
        ))
        .routes(routes!(certificate::controller::get_certificate))
        .routes(routes!(
            identifier::controller::get_identifier_list,
            identifier::controller::post_identifier
        ))
        .routes(routes!(identifier::controller::resolve_trust_entries))
        .routes(routes!(
            identifier::controller::get_identifier,
            identifier::controller::delete_identifier,
            identifier::controller::patch_identifier
        ))
        .routes(routes!(identifier::controller::post_remote_identifier))
        .routes(routes!(
            identifier::controller::post_identifier_certificates
        ))
        .routes(routes!(
            identifier::controller::delete_identifier_certificate
        ))
        .routes(routes!(
            identifier::controller::post_identifier_certificate_authorities
        ))
        .routes(routes!(
            identifier::controller::delete_identifier_certificate_authority
        ))
        .routes(routes!(did_resolver::controller::resolve_did))
        .routes(routes!(interaction::controller::handle_invitation))
        .routes(routes!(interaction::controller::issuance_accept))
        .routes(routes!(interaction::controller::issuance_reject))
        .routes(routes!(interaction::controller::issuance_refresh))
        .routes(routes!(interaction::controller::presentation_submit_v2))
        .routes(routes!(interaction::controller::propose_proof))
        .routes(routes!(interaction::controller::presentation_reject))
        .routes(routes!(interaction::controller::initiate_issuance))
        .routes(routes!(interaction::controller::continue_issuance))
        .routes(routes!(task::controller::post_task))
        .routes(routes!(
            managed_instance::controller::get_managed_instance_list
        ))
        .routes(routes!(
            managed_instance::controller::get_managed_instance_details,
            managed_instance::controller::delete_managed_instance
        ))
        .routes(routes!(
            managed_instance::controller::revoke_managed_instance
        ))
        .routes(routes!(jsonld::controller::resolve_jsonld_context))
        .routes(routes!(instance::controller::get_instance_details))
        .routes(routes!(instance::controller::instance_status))
        .routes(routes!(instance::controller::activate_remote_instance))
        .routes(routes!(instance::controller::register_remote_instance))
        .routes(routes!(statistics::controller::organisation_statistics))
        .routes(routes!(statistics::controller::issuer_statistics))
        .routes(routes!(statistics::controller::verifier_statistics))
        .routes(routes!(statistics::controller::system_statistics))
        .routes(routes!(
            statistics::controller::system_interaction_statistics
        ))
        .routes(routes!(
            statistics::controller::system_management_statistics
        ))
        .routes(routes!(
            trust_list_publication::controller::get_trust_list_publications,
            trust_list_publication::controller::post_trust_list_publication
        ))
        .routes(routes!(
            trust_list_publication::controller::get_trust_list_publication,
            trust_list_publication::controller::delete_trust_list_publication
        ))
        .routes(routes!(
            trust_list_publication::controller::get_trust_list_publication_entries,
            trust_list_publication::controller::post_trust_entry
        ))
        .routes(routes!(
            trust_list_publication::controller::patch_trust_entry,
            trust_list_publication::controller::delete_trust_entry
        ))
        .routes(routes!(
            trust_collection::controller::get_trust_collection_list,
            trust_collection::controller::post_trust_collection
        ))
        .routes(routes!(
            trust_collection::controller::get_trust_collection,
            trust_collection::controller::delete_trust_collection
        ))
        .routes(routes!(
            trust_collection::controller::get_trust_list_subscription_entries,
            trust_collection::controller::post_trust_list_subscription
        ))
        .routes(routes!(
            trust_collection::controller::delete_trust_list_subscription
        ));

    if config.enable_signature_endpoints {
        router = router
            .routes(routes!(signature::controller::create_signature))
            .routes(routes!(signature::controller::revoke_signature))
            .routes(routes!(signature::controller::signature_revocation_check));
    }

    if config.enable_qes_endpoints {
        router = router
            .routes(routes!(qes::controller::authorize))
            .routes(routes!(qes::controller::sign));
    }

    router.layer(middleware::from_fn(crate::middleware::authorization_check))
}

fn get_system_endpoints(config: &ServerConfig) -> OpenApiRouter<AppState> {
    let mut router = OpenApiRouter::default();

    if config.enable_server_info {
        router = router
            .routes(routes!(system::controller::liveness))
            .routes(routes!(system::controller::readiness))
            .routes(
                routes!(system::controller::get_build_info)
                    .layer(middleware::from_fn(crate::middleware::authorization_check)),
            );
    }

    if config.enable_metrics {
        router = router.routes(routes!(system::controller::get_metrics));
    }

    router
}

#[expect(deprecated)]
fn get_external_endpoints(config: &ServerConfig) -> OpenApiRouter<AppState> {
    if !config.enable_external_endpoints {
        return OpenApiRouter::default();
    }

    let large_external_request_body_limit = config.max_large_external_request_body_bytes;

    OpenApiRouter::default()
        .routes(routes!(
            ssi::issuance::controller::oid4vci_get_jwt_vc_issuer_metadata
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_get_issuer_metadata
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_oauth_authorization_server
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_get_credential_offer
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_create_token
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_create_credential
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_credential_notification
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_nonce
        ))
        .routes(routes!(
            ssi::issuance::final1_0::controller::oid4vci_final1_0_oauth_attestation_challenge
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_get_issuer_metadata
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_oauth_authorization_server
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_get_credential_offer
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_create_token
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_create_credential
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_nonce
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_oauth_attestation_challenge
        ))
        .routes(routes!(
            ssi::issuance::final1_0_swiyu::controller::oid4vci_final1_0_swiyu_credential_notification
        ))
        .routes(
            routes!(ssi::verification::final1_0::controller::oid4vp_final1_0_direct_post)
                .layer(DefaultBodyLimit::max(large_external_request_body_limit)),
        )
        .routes(routes!(
            ssi::verification::final1_0::controller::oid4vp_final1_0_client_metadata
        ))
        .routes(routes!(
            ssi::verification::final1_0::controller::oid4vp_final1_0_client_request
        ))
        .routes(routes!(
            ssi::verification::final1_0_swiyu::controller::oid4vp_final1_0_swiyu_client_request
        ))
        .routes(
            routes!(
                ssi::verification::final1_0_swiyu::controller::oid4vp_final1_0_swiyu_direct_post
            )
            .layer(DefaultBodyLimit::max(large_external_request_body_limit)),
        )
        .routes(routes!(ssi::controller::get_revocation_list_by_id))
        .routes(routes!(ssi::controller::get_crl_by_id))
        .routes(routes!(ssi::controller::get_did_web_document))
        .routes(routes!(ssi::controller::get_did_webvh_log))
        .routes(routes!(ssi::controller::get_json_ld_context))
        .routes(routes!(ssi::controller::get_json_ld_context_by_format))
        .routes(routes!(ssi::controller::ssi_get_credential_schema))
        .routes(routes!(ssi::controller::ssi_get_credential_schema_v2))
        .routes(routes!(
            ssi::controller::ssi_get_credential_schema_by_format_v2
        ))
        .routes(routes!(ssi::controller::ssi_get_proof_schema))
        .routes(routes!(ssi::controller::ssi_get_sd_jwt_vc_type_metadata))
        .routes(routes!(
            ssi::controller::ssi_get_sd_jwt_vc_type_metadata_v2
        ))
        .routes(routes!(ssi::controller::ssi_get_certificate_authority))
        .routes(routes!(ssi::controller::ssi_get_certificate))
        .routes(routes!(
            ssi::verifier_provider::controller::get_verification_provider
        ))
        .routes(routes!(
            ssi::wallet_provider::controller::register_wallet_unit
        ))
        .routes(routes!(
            ssi::wallet_provider::controller::activate_wallet_unit
        ))
        .routes(routes!(
            ssi::wallet_provider::controller::issue_wallet_unit_attestation
        ))
        .routes(routes!(
            ssi::wallet_provider::controller::get_wallet_provider_metadata
        ))
        .routes(routes!(ssi::instance::controller::register_instance))
        .routes(routes!(ssi::instance::controller::activate_instance))
        .routes(routes!(
            ssi::instance::controller::issue_instance_attestation
        ))
        .routes(routes!(ssi::controller::ssi_get_trust_list_publication))
        .routes(routes!(ssi::controller::ssi_get_trust_collection))
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
