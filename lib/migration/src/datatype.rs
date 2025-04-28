use sea_orm_migration::prelude::*;

pub trait ColumnDefExt {
    fn large_blob(&mut self, manager: &SchemaManager) -> &mut ColumnDef;
    fn datetime_millisecond_precision(&mut self, manager: &SchemaManager) -> &mut ColumnDef;
}

impl ColumnDefExt for ColumnDef {
    fn large_blob(&mut self, _manager: &SchemaManager) -> &mut ColumnDef {
        self.blob();

        #[cfg(feature = "mysql")]
        if matches!(
            _manager.get_database_backend(),
            sea_orm::DatabaseBackend::MySql
        ) {
            self.custom(extension::mysql::MySqlType::LongBlob);
        }

        self
    }

    fn datetime_millisecond_precision(&mut self, manager: &SchemaManager) -> &mut ColumnDef {
        let dt = match manager.get_database_backend() {
            sea_orm::DatabaseBackend::MySql => "datetime(3)",
            sea_orm::DatabaseBackend::Postgres => "timestamp(3)",
            sea_orm::DatabaseBackend::Sqlite => "datetime",
        };

        self.custom(Alias::new(dt));

        self
    }
}
