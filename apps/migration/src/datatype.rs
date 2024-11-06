use sea_orm_migration::prelude::*;

pub trait ColumnDefExt {
    fn custom_blob(&mut self, manager: &SchemaManager) -> &mut ColumnDef;
}

impl ColumnDefExt for ColumnDef {
    fn custom_blob(&mut self, _manager: &SchemaManager) -> &mut ColumnDef {
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
}
