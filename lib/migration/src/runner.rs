use sea_orm::{DatabaseBackend, TransactionError, TransactionTrait};
use sea_orm_migration::prelude::*;

use crate::Migrator;

/// Wraps DB migrations into a single transaction
/// to prevent problems with partially applied migrations
///
pub async fn run_migrations<'c, C>(db: C) -> Result<(), DbErr>
where
    C: IntoSchemaManagerConnection<'c>,
{
    let connection = db.into_schema_manager_connection();
    match connection.get_database_backend() {
        // sea-orm-migrations runs it atomic with Postgres
        DatabaseBackend::Postgres => Migrator::up(connection, None).await,

        // manual wrapping with transaction necessary for the others
        DatabaseBackend::MySql | DatabaseBackend::Sqlite => {
            let result = connection
                .transaction::<_, (), DbErr>(|txn| {
                    Box::pin(async move { Migrator::up(txn, None).await })
                })
                .await;

            match result {
                Ok(_) => Ok(()),
                Err(TransactionError::Connection(e)) => Err(e),
                Err(TransactionError::Transaction(e)) => Err(e),
            }
        }
    }
}
