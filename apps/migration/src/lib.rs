pub use sea_orm_migration::prelude::*;

mod m20230530_000001_initial;
mod m20230705_000002_revocation_none;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230530_000001_initial::Migration),
            Box::new(m20230705_000002_revocation_none::Migration),
        ]
    }
}
