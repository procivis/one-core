use sea_orm::{DatabaseConnection, DatabaseTransaction};
use sea_orm_migration::prelude::*;

pub trait ColumnDefExt {
    fn large_blob<T: HasDatabaseBackend>(&mut self, manager: &T) -> &mut ColumnDef;
    fn datetime_millisecond_precision<T: HasDatabaseBackend>(
        &mut self,
        manager: &T,
    ) -> &mut ColumnDef;
    fn datetime_second_precision<T: HasDatabaseBackend>(&mut self, manager: &T) -> &mut ColumnDef;
}

impl ColumnDefExt for ColumnDef {
    fn large_blob<T: HasDatabaseBackend>(&mut self, _manager: &T) -> &mut ColumnDef {
        self.blob();

        #[cfg(feature = "mysql")]
        if matches!(_manager.backend(), sea_orm::DatabaseBackend::MySql) {
            self.custom(extension::mysql::MySqlType::LongBlob);
        }

        self
    }

    fn datetime_millisecond_precision<T: HasDatabaseBackend>(
        &mut self,
        manager: &T,
    ) -> &mut ColumnDef {
        let dt = match manager.backend() {
            sea_orm::DatabaseBackend::MySql => "datetime(3)",
            sea_orm::DatabaseBackend::Postgres => "timestamp(3)",
            sea_orm::DatabaseBackend::Sqlite => "datetime",
        };

        self.custom(Alias::new(dt));

        self
    }

    fn datetime_second_precision<T: HasDatabaseBackend>(&mut self, manager: &T) -> &mut ColumnDef {
        let dt = match manager.backend() {
            sea_orm::DatabaseBackend::MySql => "datetime(0)",
            sea_orm::DatabaseBackend::Postgres => "timestamp(0)",
            sea_orm::DatabaseBackend::Sqlite => "datetime",
        };

        self.custom(Alias::new(dt));

        self
    }
}

pub(super) trait HasDatabaseBackend {
    fn backend(&self) -> sea_orm::DatabaseBackend;
}

impl HasDatabaseBackend for SchemaManager<'_> {
    fn backend(&self) -> sea_orm::DatabaseBackend {
        self.get_database_backend()
    }
}

impl HasDatabaseBackend for SchemaManagerConnection<'_> {
    fn backend(&self) -> sea_orm::DatabaseBackend {
        self.get_database_backend()
    }
}

impl HasDatabaseBackend for DatabaseConnection {
    fn backend(&self) -> sea_orm::DatabaseBackend {
        self.get_database_backend()
    }
}

impl HasDatabaseBackend for DatabaseTransaction {
    fn backend(&self) -> sea_orm::DatabaseBackend {
        self.get_database_backend()
    }
}

pub(crate) fn uuid_char<T: IntoIden>(ident: T) -> ColumnDef {
    ColumnDef::new(ident).char_len(36).not_null().take()
}

pub(crate) fn uuid_char_null<T: IntoIden>(ident: T) -> ColumnDef {
    ColumnDef::new(ident).char_len(36).null().take()
}

pub(crate) fn timestamp<T: IntoIden, DB: HasDatabaseBackend>(ident: T, manager: &DB) -> ColumnDef {
    ColumnDef::new(ident)
        .datetime_millisecond_precision(manager)
        .not_null()
        .take()
}

pub(crate) fn timestamp_null<T: IntoIden, DB: HasDatabaseBackend>(
    ident: T,
    manager: &DB,
) -> ColumnDef {
    ColumnDef::new(ident)
        .datetime_millisecond_precision(manager)
        .null()
        .take()
}
