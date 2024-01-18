pub use sea_orm_migration::prelude::*;

mod m20240110_000001_initial;
mod m20240115_093859_unique_did_name_and_key_name_in_org;
mod m20240116_110014_unique_did_in_organisation;
mod m20240116_153515_make_name_indexes_unique;
mod m20240118_070610_credential_add_role;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20240110_000001_initial::Migration),
            Box::new(m20240115_093859_unique_did_name_and_key_name_in_org::Migration),
            Box::new(m20240116_110014_unique_did_in_organisation::Migration),
            Box::new(m20240116_153515_make_name_indexes_unique::Migration),
            Box::new(m20240118_070610_credential_add_role::Migration),
        ]
    }
}
