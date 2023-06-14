#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::{IpAddr, SocketAddr};
use std::panic;

use axum::routing::{delete, get};
use axum::Router;
use sea_orm::DatabaseConnection;
use shadow_rs::shadow;
use tower_http::trace::{self, TraceLayer};
use tracing::{info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use migration::{Migrator, MigratorTrait};

mod endpoints;
mod entities;
mod list_query;

use endpoints::data_model;

#[cfg(test)]
mod test_utilities;

async fn setup_database_and_connection() -> Result<DatabaseConnection, sea_orm::DbErr> {
    let db = sea_orm::Database::connect(envmnt::get_or_panic("DATABASE_URL")).await?;
    Migrator::up(&db, None).await?;

    Ok(db)
}

#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[derive(OpenApi)]
    #[openapi(
        paths(
            endpoints::delete_credential_schema,
            endpoints::get_credential_schema_details,
            endpoints::get_credential_schema,
            endpoints::post_credential_schema,
            endpoints::post_proof_schema,
            endpoints::get_proof_schemas,
            endpoints::delete_proof_schema,
            endpoints::get_build_info
        ),
        components(
            schemas(data_model::CreateCredentialSchemaRequestDTO,
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
                    data_model::Format,
                    data_model::Datatype,
                    list_query::SortDirection)
        ),
        modifiers(),
        tags(
            (name = "credential_schema_management", description = "Credential schema management"),
            (name = "proof_schema_management", description = "Proof schema management"),
            (name = "other", description = "Other utility endpoints"),
        )
    )]
    struct ApiDoc;

    config_tracing();
    log_build_info();

    let db = setup_database_and_connection().await?;
    let state = AppState { db };

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route(
            "/api/credential-schema/v1/:id",
            delete(endpoints::delete_credential_schema),
        )
        .route(
            "/api/credential-schema/v1/:id",
            get(endpoints::get_credential_schema_details),
        )
        .route(
            "/api/credential-schema/v1",
            get(endpoints::get_credential_schema).post(endpoints::post_credential_schema),
        )
        .route(
            "/api/proof-schema/v1/:id",
            delete(endpoints::delete_proof_schema),
        )
        .route(
            "/api/proof-schema/v1",
            get(endpoints::get_proof_schemas).post(endpoints::post_proof_schema),
        )
        .route("/build_info", get(endpoints::get_build_info))
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
