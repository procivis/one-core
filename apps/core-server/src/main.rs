#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{HeaderValue, Request, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use figment::{providers::Env, Figment};
use one_core::OneCore;
use serde::Deserialize;
use shadow_rs::shadow;
use sql_data_provider::DataLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, info_span, Span};
use tracing_subscriber::fmt::format::FmtSpan;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

mod config;
pub(crate) mod data_model;
pub(crate) mod dto;
pub(crate) mod endpoint;
pub(crate) mod mapper;
pub(crate) mod serialize;

use endpoint::{
    delete_proof_schema, get_config, get_credential, get_proof, get_proof_schema, misc,
    post_credential, post_proof, post_proof_schema, share_credential, share_proof,
    ssi_post_handle_invitation, ssi_post_issuer_connect, ssi_post_verifier_connect,
    ssi_post_verifier_reject_proof_request, ssi_post_verifier_submit,
};

use crate::endpoint::{credential_schema, did, organisation};

#[derive(Clone)]
struct AppState {
    pub core: OneCore,
}

#[derive(Deserialize, Debug, Clone)]
struct Config {
    config_file: String,
    database_url: String,
    server_ip: Option<IpAddr>,
    server_port: Option<u16>,
    trace_json: Option<bool>,
    auth_token: String,
    core_base_url: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            endpoint::organisation::controller::post_organisation,
            endpoint::organisation::controller::get_organisation,
            endpoint::organisation::controller::get_organisations,

            endpoint::credential_schema::controller::delete_credential_schema,
            endpoint::credential_schema::controller::get_credential_schema,
            endpoint::credential_schema::controller::get_credential_schema_list,
            endpoint::credential_schema::controller::post_credential_schema,

            endpoint::did::controller::get_did,
            endpoint::did::controller::get_did_list,
            endpoint::did::controller::post_did,

            endpoint::get_config::get_config,
            endpoint::get_credential::get_credentials,
            endpoint::get_credential::get_credential_details,
            endpoint::post_credential::post_credential,
            endpoint::share_credential::share_credential,
            endpoint::share_proof::share_proof,
            endpoint::post_proof_schema::post_proof_schema,
            endpoint::post_proof::post_proof,
            endpoint::get_proof_schema::get_proof_schema_details,
            endpoint::get_proof_schema::get_proof_schemas,
            endpoint::delete_proof_schema::delete_proof_schema,
            endpoint::get_proof::get_proof_details,
            endpoint::get_proof::get_proofs,
            endpoint::misc::get_build_info,
            endpoint::ssi_post_handle_invitation::ssi_post_handle_invitation,
            endpoint::ssi_post_issuer_connect::ssi_issuer_connect,
            endpoint::ssi_post_verifier_connect::ssi_verifier_connect,
            endpoint::ssi_post_verifier_reject_proof_request::ssi_post_verifier_reject_proof_request,
            endpoint::ssi_post_verifier_submit::ssi_verifier_submit,
        ),
        components(
            schemas(
                endpoint::organisation::dto::CreateOrganisationRequestRestDTO,
                endpoint::organisation::dto::CreateOrganisationResponseRestDTO,
                endpoint::organisation::dto::GetOrganisationDetailsResponseRestDTO,

                endpoint::credential_schema::dto::CreateCredentialSchemaRequestRestDTO,
                endpoint::credential_schema::dto::CreateCredentialSchemaResponseRestDTO,
                endpoint::credential_schema::dto::CredentialClaimSchemaRequestRestDTO,
                endpoint::credential_schema::dto::CredentialClaimSchemaResponseRestDTO,
                endpoint::credential_schema::dto::CredentialSchemaResponseRestDTO,
                endpoint::credential_schema::dto::CredentialSchemaListValueResponseRestDTO,

                endpoint::did::dto::CreateDidRequestRestDTO,
                endpoint::did::dto::CreateDidResponseRestDTO,
                endpoint::did::dto::GetDidResponseRestDTO,
                endpoint::did::dto::DidType,
                dto::common::GetDidsResponseRestDTO,

                dto::common::GetCredentialsResponseDTO,
                dto::common::GetCredentialSchemaResponseDTO,
                dto::common::GetProofSchemaResponseDTO,
                dto::common::GetProofsResponseDTO,

                dto::common::SortDirection,

                data_model::DetailCredentialResponseDTO,
                data_model::ListCredentialSchemaResponseDTO,
                data_model::DetailCredentialClaimResponseDTO,
                data_model::CredentialState,
                data_model::CredentialRequestDTO,
                data_model::EntityResponseDTO,
                data_model::EntityShareResponseDTO,
                data_model::CredentialRequestClaimDTO,
                data_model::Transport,
                data_model::CreateProofSchemaRequestDTO,
                data_model::CreateProofSchemaResponseDTO,
                data_model::CreateProofRequestDTO,
                data_model::CreateProofResponseDTO,
                data_model::ClaimProofSchemaRequestDTO,
                data_model::ProofSchemaResponseDTO,
                data_model::ProofClaimSchemaResponseDTO,
                data_model::ProofsDetailResponseDTO,

                data_model::ConnectIssuerResponseDTO,
                data_model::ConnectVerifierResponseDTO,
                data_model::ProofClaimResponseDTO,
                data_model::ProofDetailsResponseDTO,
                data_model::ConnectRequestDTO,
                data_model::DetailProofClaimDTO,
                data_model::DetailProofSchemaDTO,
                data_model::DetailProofClaimSchemaDTO,
                data_model::ProofRequestQueryParams,
                data_model::HandleInvitationRequestDTO,
                data_model::ProofRequestState,
                dto::response::config::ConfigDTO
            )
        ),
        modifiers(),
        tags(
            (name = "credential_schema_management", description = "Credential schema management"),
            (name = "proof_schema_management", description = "Proof schema management"),
            (name = "ssi", description = "SSI"),
            (name = "other", description = "Other utility endpoints"),
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
                        .description(Some("Provide bearer token"))
                        .build(),
                ),
            )
        }
    }

    let config: Config = Figment::new()
        .merge(Env::raw())
        .extract()
        .unwrap_or_else(|e| {
            panic!("Failed to parse config: {}", e);
        });

    config_tracing(&config);
    log_build_info();

    shadow!(build);
    let mut documentation = ApiDoc::openapi();
    let local_version = format!("{}-{}", build::PKG_VERSION, build::SHORT_COMMIT);
    let app_version = build::APP_VERSION.unwrap_or(&local_version);
    documentation.info.version = app_version.to_owned();

    let config_path = PathBuf::from(&config.config_file);
    let unparsed_config = config::load_config(&config_path).expect("Failed to load config.yml");
    let core = OneCore::new(
        Arc::new(DataLayer::create(&config.database_url).await),
        unparsed_config,
    )
    .expect("Failed to parse config");

    let state = AppState { core };

    let protected = Router::new()
        .route("/api/config/v1", get(get_config::get_config))
        .route(
            "/api/credential/v1",
            get(get_credential::get_credentials).post(post_credential::post_credential),
        )
        .route(
            "/api/credential/v1/:id",
            get(get_credential::get_credential_details),
        )
        .route(
            "/api/credential/v1/:id/share",
            post(share_credential::share_credential),
        )
        .route(
            "/api/proof-request/v1/:id/share",
            post(share_proof::share_proof),
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
            delete(delete_proof_schema::delete_proof_schema)
                .get(get_proof_schema::get_proof_schema_details),
        )
        .route(
            "/api/proof-schema/v1",
            get(get_proof_schema::get_proof_schemas).post(post_proof_schema::post_proof_schema),
        )
        .route(
            "/api/proof-request/v1",
            post(post_proof::post_proof).get(get_proof::get_proofs),
        )
        .route(
            "/api/proof-request/v1/:id",
            get(get_proof::get_proof_details),
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
        .route("/api/did/v1", get(did::controller::get_did_list))
        .route("/api/did/v1", post(did::controller::post_did))
        .layer(middleware::from_fn(bearer_check));

    let unprotected = Router::new()
        .route(
            "/ssi/handle-invitation/v1",
            post(ssi_post_handle_invitation::ssi_post_handle_invitation),
        )
        .route(
            "/ssi/temporary-issuer/v1/connect",
            post(ssi_post_issuer_connect::ssi_issuer_connect),
        )
        .route(
            "/ssi/temporary-verifier/v1/connect",
            post(ssi_post_verifier_connect::ssi_verifier_connect),
        )
        .route(
            "/ssi/temporary-verifier/v1/submit",
            post(ssi_post_verifier_submit::ssi_verifier_submit),
        )
        .route(
            "/ssi/temporary-verifier/v1/reject",
            post(ssi_post_verifier_reject_proof_request::ssi_post_verifier_reject_proof_request),
        );

    let technical_endpoints = Router::new()
        .route("/build-info", get(misc::get_build_info))
        .route("/health", get(misc::health_check));

    let app = Router::new()
        .merge(protected)
        .merge(unprotected)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request<_>| {
                    let headers = request.headers();
                    let default_header_value = "NOT PROVIDED";
                    let default_header = HeaderValue::from_static(default_header_value);

                    let request_id = headers
                        .get("x-request-id")
                        .unwrap_or(&default_header)
                        .to_str()
                        .unwrap_or(default_header_value)
                        .to_string();
                    let session_id = headers
                        .get("x-session-id")
                        .unwrap_or(&default_header)
                        .to_str()
                        .unwrap_or(default_header_value)
                        .to_string();

                    let method = request.method().to_string();

                    info_span!(
                        "http_request",
                        method = method,
                        path = request.uri().path(),
                        service = "one-core",
                        RequestId = request_id,
                        SessionId = session_id,
                    )
                })
                .on_request(|request: &Request<_>, _span: &Span| {
                    tracing::debug!(
                        "SERVICE CALL START {} {}",
                        request.method(),
                        request.uri().path()
                    )
                })
                .on_response(|response: &Response<_>, _latency: Duration, _span: &Span| {
                    tracing::debug!("SERVICE CALL END {}", response.status())
                }),
        )
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", documentation))
        .merge(technical_endpoints)
        .layer(Extension(config.clone()))
        .with_state(state);

    let ip = config
        .server_ip
        .unwrap_or(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)));

    let port = config.server_port.unwrap_or(3000);

    let addr = SocketAddr::new(ip, port);

    info!("Starting server at http://{addr}");

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

fn log_build_info() {
    shadow!(build);
    info!("Build target: {}", build::BUILD_RUST_CHANNEL);
    info!("Build time: {}", build::BUILD_TIME);
    info!("Branch: {}", build::BRANCH);
    info!("Tag: {}", build::TAG);
    info!("Commit: {}", build::COMMIT_HASH);
    info!("Rust version: {}", build::RUST_VERSION);
    info!("Pipeline ID: {}", build::CI_PIPELINE_ID);
}

fn config_tracing(config: &Config) {
    // Create a filter based on the log level
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("debug"))
        .expect("Failed to create env filter");

    if config.trace_json.unwrap_or_default() {
        let subscriber: tracing_subscriber::FmtSubscriber<
            tracing_subscriber::fmt::format::JsonFields,
            tracing_subscriber::fmt::format::Format<tracing_subscriber::fmt::format::Json>,
            tracing_subscriber::EnvFilter,
        > = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_span_events(FmtSpan::CLOSE)
            .json()
            .flatten_event(true)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("Tracing subscriber initialized.");
    } else {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_span_events(FmtSpan::CLOSE)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("Tracing subscriber initialized.");
    };

    panic::set_hook(Box::new(|p| {
        tracing::error!("PANIC! Error: {p}");
    }));
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
        tracing::error!("Authorization header not found.");
        return Err(StatusCode::UNAUTHORIZED);
    };

    let mut split = auth_header.split(' ');
    let auth_type = split.next().unwrap_or_default();
    let token = split.next().unwrap_or_default();

    if auth_type == "Bearer" && !token.is_empty() && token == config.auth_token {
        request.extensions_mut().insert(Authorized {});
    } else {
        tracing::error!("Could not authorize request. Incorrect authorization method or token.");
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}
