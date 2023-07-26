pub use sea_orm_migration::prelude::*;

mod m20230530_000001_initial;
mod m20230705_000002_revocation_none;
mod m20230707_000003_unique_schema_name;
mod m20230707_000004_add_credential;
mod m20230720_000005_unique_did_value;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230530_000001_initial::Migration),
            Box::new(m20230705_000002_revocation_none::Migration),
            Box::new(m20230707_000003_unique_schema_name::Migration),
            Box::new(m20230707_000004_add_credential::Migration),
            Box::new(m20230720_000005_unique_did_value::Migration),
        ]
    }
}
