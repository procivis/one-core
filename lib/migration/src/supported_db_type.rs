use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr};
use sea_orm_migration::prelude::*;
use strum::Display;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Display)]
pub enum SupportedDbType {
    MySql,
    Postgres,
    Sqlite,
}

/// Filters unsupported DB types
/// Panics if unsupported DB type used
pub trait WithSupportedDbType {
    fn supported_db_type(&self) -> SupportedDbType;
}

impl WithSupportedDbType for SchemaManager<'_> {
    fn supported_db_type(&self) -> SupportedDbType {
        #[expect(clippy::expect_used)]
        self.get_database_backend()
            .try_into()
            .expect("Unsupported DB type")
    }
}

impl WithSupportedDbType for SchemaManagerConnection<'_> {
    fn supported_db_type(&self) -> SupportedDbType {
        #[expect(clippy::expect_used)]
        self.get_database_backend()
            .try_into()
            .expect("Unsupported DB type")
    }
}

impl WithSupportedDbType for DatabaseConnection {
    fn supported_db_type(&self) -> SupportedDbType {
        #[expect(clippy::expect_used)]
        self.get_database_backend()
            .try_into()
            .expect("Unsupported DB type")
    }
}

impl WithSupportedDbType for DatabaseTransaction {
    fn supported_db_type(&self) -> SupportedDbType {
        #[expect(clippy::expect_used)]
        self.get_database_backend()
            .try_into()
            .expect("Unsupported DB type")
    }
}

impl TryFrom<DatabaseBackend> for SupportedDbType {
    type Error = DbErr;

    fn try_from(value: DatabaseBackend) -> Result<Self, Self::Error> {
        Ok(match value {
            DatabaseBackend::MySql => Self::MySql,
            DatabaseBackend::Postgres => Self::Postgres,
            DatabaseBackend::Sqlite => Self::Sqlite,
            // non-exhaustive
            other => {
                return Err(DbErr::BackendNotSupported {
                    db: other.as_str(),
                    ctx: "Unsupported DB type",
                });
            }
        })
    }
}
