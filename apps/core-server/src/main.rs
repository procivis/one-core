#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::{IpAddr, SocketAddr};
use std::panic;

use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, post};
use axum::Router;
use one_core::OneCore;
use shadow_rs::shadow;
use tower_http::trace::{self, TraceLayer};
use tracing::{info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

mod data_model;
mod endpoints;

#[derive(Clone)]
struct AppState {
    pub core: OneCore,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            endpoints::post_credential,
            endpoints::delete_credential_schema,
            endpoints::get_credential_schema_details,
            endpoints::get_credential_schema,
            endpoints::post_credential_schema,
            endpoints::post_proof_schema,
            endpoints::get_proof_schema_details,
            endpoints::get_proof_schemas,
            endpoints::delete_proof_schema,
            endpoints::post_organisation,
            endpoints::get_organisation_details,
            endpoints::get_organisations,
            endpoints::get_build_info
        ),
        components(
            schemas(data_model::CredentialRequestDTO,
                    data_model::EntityResponseDTO,
                    data_model::CredentialRequestClaimDTO,
                    data_model::Transport,
                    data_model::CreateCredentialSchemaRequestDTO,
                    data_model::CredentialClaimSchemaRequestDTO,
                    data_model::GetCredentialClaimSchemaResponseDTO,
                    data_model::CredentialSchemaResponseDTO,
                    data_model::CredentialClaimSchemaResponseDTO,
                    data_model::CreateProofSchemaRequestDTO,
                    data_model::CreateProofSchemaResponseDTO,
                    data_model::ClaimProofSchemaRequestDTO,
                    data_model::RevocationMethod,
                    data_model::ProofSchemaResponseDTO,
                    data_model::GetProofSchemaResponseDTO,
                    data_model::ProofClaimSchemaResponseDTO,
                    data_model::CreateOrganisationRequestDTO,
                    data_model::CreateOrganisationResponseDTO,
                    data_model::GetOrganisationDetailsResponseDTO,
                    data_model::Format,
                    data_model::Datatype,
                    data_model::SortDirection)
        ),
        modifiers(),
        tags(
            (name = "credential_schema_management", description = "Credential schema management"),
            (name = "proof_schema_management", description = "Proof schema management"),
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

    config_tracing();
    log_build_info();

    shadow!(build);
    let mut documentation = ApiDoc::openapi();
    let local_version = format!("{}-{}", build::PKG_VERSION, build::SHORT_COMMIT);
    let app_version = build::APP_VERSION.unwrap_or(&local_version);
    documentation.info.version = app_version.to_owned();

    let database_url = envmnt::get_or_panic("DATABASE_URL");
    let core = OneCore::new(&database_url).await;

    let state = AppState { core };

    let protected = Router::new()
        .route("/api/credential/v1", post(endpoints::post_credential))
        .route(
            "/api/credential-schema/v1/:id",
            delete(endpoints::delete_credential_schema)
                .get(endpoints::get_credential_schema_details),
        )
        .route(
            "/api/credential-schema/v1",
            get(endpoints::get_credential_schema).post(endpoints::post_credential_schema),
        )
        .route(
            "/api/proof-schema/v1/:id",
            delete(endpoints::delete_proof_schema).get(endpoints::get_proof_schema_details),
        )
        .route(
            "/api/proof-schema/v1",
            get(endpoints::get_proof_schemas).post(endpoints::post_proof_schema),
        )
        .route(
            "/api/organisation/v1",
            get(endpoints::get_organisations).post(endpoints::post_organisation),
        )
        .route(
            "/api/organisation/v1/:id",
            get(endpoints::get_organisation_details),
        )
        .layer(middleware::from_fn(bearer_check));

    let unprotected = Router::new()
        .route("/build-info", get(endpoints::get_build_info))
        .route("/health", get(endpoints::health_check));

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", documentation))
        .merge(protected)
        .merge(unprotected)
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::DEBUG))
                .on_request(trace::DefaultOnRequest::new().level(Level::DEBUG))
                .on_response(trace::DefaultOnResponse::new().level(Level::DEBUG)),
        );

    let ip: IpAddr = envmnt::get_or("SERVER_IP", "0.0.0.0")
        .parse()
        .expect("SERVER_IP parsing failed");

    let port = envmnt::get_u16("SERVER_PORT", 3000);

    let addr = SocketAddr::new(ip, port);

    info!("Starting server at {addr}");

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

fn config_tracing() {
    // Create a filter based on the log level
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("debug"))
        .expect("Failed to create env filter");

    if envmnt::is_or("TRACE_JSON", false) {
        let subscriber = tracing_subscriber::fmt()
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

async fn bearer_check<B>(mut request: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
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

    if auth_type == "Bearer" && !token.is_empty() && token == envmnt::get_or("AUTH_TOKEN", "") {
        request.extensions_mut().insert(Authorized {});
    } else {
        tracing::error!("Could not authorize request. Incorrect authorization method or token.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}
