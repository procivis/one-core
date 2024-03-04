pub use sea_orm_migration::prelude::*;

mod m20240110_000001_initial;
mod m20240115_093859_unique_did_name_and_key_name_in_org;
mod m20240116_110014_unique_did_in_organisation;
mod m20240116_153515_make_name_indexes_unique;
mod m20240118_070610_credential_add_role;
mod m20240123_124653_proof_state_enum_rename_offered_to_requested;
mod m20240129_112026_add_unique_index_on_credential_schema_name_organisation_deleted_at;
mod m20240129_115447_add_unique_index_on_proof_schema_name_organisation_deleted_at;
mod m20240130_105023_add_history;
mod m20240130_153529_add_pending_variant_to_history_action_enum_in_history_table;
mod m20240209_144950_add_verifier_key_id_to_proof;
mod m20240220_082229_add_lvvc_table;

pub(crate) mod m20240209_144950_models;
mod m20240223_094129_validity_constraint_in_proof_schema;
mod m20240223_103849_add_backup_columns;
mod m20240229_134129_wallet_storage_type_credential_schema;

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
            Box::new(m20240123_124653_proof_state_enum_rename_offered_to_requested::Migration),
            Box::new(m20240129_112026_add_unique_index_on_credential_schema_name_organisation_deleted_at::Migration),
            Box::new(m20240129_115447_add_unique_index_on_proof_schema_name_organisation_deleted_at::Migration),
            Box::new(m20240130_105023_add_history::Migration),
            Box::new(m20240130_153529_add_pending_variant_to_history_action_enum_in_history_table::Migration),
            Box::new(m20240209_144950_add_verifier_key_id_to_proof::Migration),
            Box::new(m20240220_082229_add_lvvc_table::Migration),
            Box::new(m20240223_094129_validity_constraint_in_proof_schema::Migration),
            Box::new(m20240223_103849_add_backup_columns::Migration),
            Box::new(m20240229_134129_wallet_storage_type_credential_schema::Migration),
        ]
    }
}
