#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::{IpAddr, SocketAddr};
use std::panic;

use axum::routing::delete;
use axum::{routing::post, Router};
use sea_orm::DatabaseConnection;
use tower_http::trace::{self, TraceLayer};
use tracing::{info, Level};
use tracing_subscriber::fmt::format::FmtSpan;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use migration::{Migrator, MigratorTrait};

mod create_credential_schema;
mod delete_credential_schema;
mod delete_proof_schema;
mod endpoints;

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
            endpoints::post_credential_schema
        ),
        components(
            schemas(one_core::data_model::CreateCredentialSchemaRequestDTO,
                    one_core::data_model::RevocationMethod,
                    one_core::data_model::Format,
                    one_core::data_model::CredentialClaimSchemaRequestDTO,
                    one_core::data_model::Datatype)
        ),
        modifiers(),
        tags(
            (name = "one_core_mock_server", description = "one-core mock server API")
        )
    )]
    struct ApiDoc;

    config_tracing();

    let db = setup_database_and_connection().await?;
    let state = AppState { db };

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route(
            "/api/credential-schema/v1/:id",
            delete(endpoints::delete_credential_schema),
        )
        .route(
            "/api/credential-schema/v1",
            post(endpoints::post_credential_schema),
        )
        .route(
            "/api/proof-schema/v1/:id",
            delete(endpoints::delete_proof_schema),
        )
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
