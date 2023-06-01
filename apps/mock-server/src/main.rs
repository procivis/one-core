#![cfg_attr(feature = "strict", deny(warnings))]

use std::net::SocketAddr;

use axum::routing::delete;
use axum::{routing::post, Router};
use sea_orm::DatabaseConnection;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use migration::{Migrator, MigratorTrait};

mod create_credential_schema;
mod delete_credential_schema;
mod endpoints;

#[cfg(test)]
mod test_utilities;

async fn setup_database_and_connection() -> Result<DatabaseConnection, sea_orm::DbErr> {
    const DATABASE_URL: &str = "sqlite::memory:";

    let db = sea_orm::Database::connect(DATABASE_URL).await?;
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
                    one_core::data_model::CreateCredentialSchemaRequestDTO,
                    one_core::data_model::CredentialClaimSchemaRequestDTO,
                    one_core::data_model::Datatype)
        ),
        modifiers(),
        tags(
            (name = "one_core_mock_server", description = "one-core mock server API")
        )
    )]
    struct ApiDoc;

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
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}
