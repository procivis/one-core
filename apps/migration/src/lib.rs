pub use sea_orm_migration::prelude::*;

mod m20230530_000001_create_credential_schema_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(
            m20230530_000001_create_credential_schema_table::Migration,
        )]
    }
}
