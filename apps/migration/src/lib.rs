use sea_orm::{DatabaseBackend, TransactionError, TransactionTrait};
use sea_orm_migration::migrator::MigratorTrait;
use sea_orm_migration::prelude::*;

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
mod m20240305_081435_proof_input_schema;
mod m20240305_110029_suspend_credential_state;
mod m20240306_122440_add_backup_restored;
mod m20240306_124716_proof_input_claim_schema;
mod m20240307_071419_proof_input_claim_schema_required;
mod m20240307_093000_add_purpose_to_revocation_list;
mod m20240307_103000_add_reactivated_history_action;
mod m20240308_115228_add_metadata_to_history;
mod m20240314_101347_recreate_proof_input_schema_and_proof_input_claim_schema_tables;
mod m20240314_141907_remove_proof_schema_claim_schema_relation;
mod m20240319_105859_typed_credential_schema;
mod m20240321_154846_add_layout_type_and_layout_properties_to_credential_schema;
mod m20240424_124450_add_json_ld_context;
mod m20240514_070446_add_trust_model;
mod m20240522_081021_fix_trust_priority_type;
mod m20240522_093357_add_errored_variant_to_history_action_enum_in_history_table;
mod m20240523_093449_add_cascade_to_trust_entity_fk;
mod m20240528_090016_rename_lvvc_table_to_validity_credential;
mod m20240528_092240_add_type_field_to_validity_credential_table;
mod m20240528_093449_make_trust_columns_optional;
mod m20240528_120000_add_shared_imported_history_action;
mod m20240611_110000_introduce_path_and_array;
mod m20240625_090000_proof_exchange_to_transport;
mod m20240628_121021_fix_trust_logo;
mod m20240702_071021_fix_entity_id;
mod m20240710_091021_fix_unique_constraint_schema_id;
mod m20240726_084216_rename_jsonldcontextprovider_to_cacheprovider;
mod m20240802_121405_soft_delete_jsonld_classic_credentials;
mod m20240805_124842_fix_remoteentity_key_type;
mod m20240812_155510_fix_schema_unique_constraint;
mod m20240905_114351_add_claims_removed_event;
mod m20240920_115859_import_url;
mod m20240925_130000_introduce_allow_suspension;
mod m20241001_102526_make_import_source_url_optional_proof_schema_table;
mod m20241001_114629_soft_delete_bbsplus;
mod m20241009_153829_organisation_id_added_to_interaction;

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
            Box::new(m20240305_081435_proof_input_schema::Migration),
            Box::new(m20240305_110029_suspend_credential_state::Migration),
            Box::new(m20240306_122440_add_backup_restored::Migration),
            Box::new(m20240306_124716_proof_input_claim_schema::Migration),
            Box::new(m20240307_071419_proof_input_claim_schema_required::Migration),
            Box::new(m20240307_093000_add_purpose_to_revocation_list::Migration),
            Box::new(m20240307_103000_add_reactivated_history_action::Migration),
            Box::new(m20240308_115228_add_metadata_to_history::Migration),
            Box::new(m20240314_101347_recreate_proof_input_schema_and_proof_input_claim_schema_tables::Migration),
            Box::new(m20240314_141907_remove_proof_schema_claim_schema_relation::Migration),
            Box::new(m20240321_154846_add_layout_type_and_layout_properties_to_credential_schema::Migration),
            Box::new(m20240319_105859_typed_credential_schema::Migration),
            Box::new(m20240424_124450_add_json_ld_context::Migration),
            Box::new(m20240514_070446_add_trust_model::Migration),
            Box::new(m20240522_093357_add_errored_variant_to_history_action_enum_in_history_table::Migration),
            Box::new(m20240522_081021_fix_trust_priority_type::Migration),
            Box::new(m20240523_093449_add_cascade_to_trust_entity_fk::Migration),
            Box::new(m20240528_093449_make_trust_columns_optional::Migration),
            Box::new(m20240528_120000_add_shared_imported_history_action::Migration),
            Box::new(m20240528_090016_rename_lvvc_table_to_validity_credential::Migration),
            Box::new(m20240528_092240_add_type_field_to_validity_credential_table::Migration),
            Box::new(m20240611_110000_introduce_path_and_array::Migration),
            Box::new(m20240625_090000_proof_exchange_to_transport::Migration),
            Box::new(m20240628_121021_fix_trust_logo::Migration),
            Box::new(m20240702_071021_fix_entity_id::Migration),
            Box::new(m20240710_091021_fix_unique_constraint_schema_id::Migration),
            Box::new(m20240726_084216_rename_jsonldcontextprovider_to_cacheprovider::Migration),
            Box::new(m20240802_121405_soft_delete_jsonld_classic_credentials::Migration),
            Box::new(m20240805_124842_fix_remoteentity_key_type::Migration),
            Box::new(m20240812_155510_fix_schema_unique_constraint::Migration),
            Box::new(m20240905_114351_add_claims_removed_event::Migration),
            Box::new(m20240920_115859_import_url::Migration),
            Box::new(m20240925_130000_introduce_allow_suspension::Migration),
            Box::new(m20241001_102526_make_import_source_url_optional_proof_schema_table::Migration),
            Box::new(m20241001_114629_soft_delete_bbsplus::Migration),
            Box::new(m20241009_153829_organisation_id_added_to_interaction::Migration),
        ]
    }
}

/// Wraps DB migrations into a single transaction
/// to prevent problems with partially applied migrations
///
pub async fn run_migrations<'c, C>(db: C) -> Result<(), DbErr>
where
    C: IntoSchemaManagerConnection<'c>,
{
    let connection = db.into_schema_manager_connection();
    match connection.get_database_backend() {
        // sea-orm-migrations runs it atomic with Postgres
        DatabaseBackend::Postgres => Migrator::up(connection, None).await,

        // manual wrapping with transaction necessary for the others
        DatabaseBackend::MySql | DatabaseBackend::Sqlite => {
            let result = connection
                .transaction::<_, (), DbErr>(|txn| {
                    Box::pin(async move { Migrator::up(txn, None).await })
                })
                .await;

            match result {
                Ok(_) => Ok(()),
                Err(TransactionError::Connection(e)) => Err(e),
                Err(TransactionError::Transaction(e)) => Err(e),
            }
        }
    }
}
