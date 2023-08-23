pub use sea_orm_migration::prelude::*;

mod m20230530_000001_initial;
mod m20230818_000002_get_rid_of_datatype_enum;
mod m20230821_000003_get_rid_of_enums;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230530_000001_initial::Migration),
            Box::new(m20230818_000002_get_rid_of_datatype_enum::Migration),
            Box::new(m20230821_000003_get_rid_of_enums::Migration),
        ]
    }
}
