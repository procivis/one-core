pub use sea_orm_migration::prelude::*;

mod sqlite_complete_migration;

mod m20230530_000001_initial;
mod m20230619_094909_organisation_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230530_000001_initial::Migration),
            Box::new(m20230619_094909_organisation_table::Migration),
        ]
    }
}

pub struct SQLiteMigrator;

#[async_trait::async_trait]
impl MigratorTrait for SQLiteMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(sqlite_complete_migration::Migration)]
    }
}
