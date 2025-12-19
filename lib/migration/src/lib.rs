use sea_orm_migration::migrator::MigratorTrait;
use sea_orm_migration::prelude::*;

pub(crate) mod datatype;
pub(crate) mod models_20240209;
pub(crate) mod models_20241210;
pub mod runner;

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
mod m20241031_095859_redirect_uri_length;
mod m20241101_092048_clear_statuslist_cache;
mod m20241104_085435_rename_sdjwt_with_underscore;
mod m20241115_090000_add_media_type_to_remote_entity;
mod m20241119_071036_add_revocation_format_type;
mod m20241119_095859_redirect_uri_length;
mod m20241120_164124_update_trust_anchor_and_entity_tables;
mod m20241125_170909_trust_anchor_publisher_reference_mandatory;
mod m20241126_105830_drop_reactivated_history_action;
mod m20241126_154001_update_remote_entity_type_enum_in_remote_entity_cache_table;
mod m20241127_112144_did_organisation_id_optional;
mod m20241203_08000_update_remote_entity_type_enum_trust_list;
mod m20241210_154315_remove_proof_state_table;
mod m20241212_08000_migrate_credential_state;
mod m20241218_134714_history_entity_id_index;
mod m20241224_08000_fix_index_for_credential_schema;
mod m20250107_134349_did_sd_jwt_vc_issuer_metadata;
mod m20250113_115815_trust_entity_unique_did;
mod m20250117_085705_remove_state_tables;
mod m20250124_152249_update_status_list_enum_variant_in_remote_entity_type_table;
mod m20250203_143642_add_rse_storage_type;
mod m20250205_120540_rename_bitstring_status_list_type_in_revocation_list_table;
mod m20250214_102249_missing_remote_entity_type;
mod m20250218_094713_add_trust_entity_history_changes;
mod m20250218_161915_add_proof_role;
mod m20250220_080800_add_external_credential_schema_flag;
mod m20250220_131625_add_proof_state_retracted;
mod m20250314_114529_rename_transport_to_exchange;
mod m20250317_133346_add_org_name;
mod m20250319_101601_add_updated_history_action;
mod m20250324_150815_add_name_to_history_table;
mod m20250327_141601_add_new_history_action;
mod m20250331_115152_add_history_target;
mod m20250331_143210_rename_es256_to_ecdsa;
mod m20250401_110914_add_log_column_to_did_table;
mod m20250401_140204_add_reactivated_history_enum;
mod m20250403_083609_exchange_rename;
mod m20250414_111854_add_update_key_enum_to_key_did;
mod m20250426_093351_large_blob;
mod m20250429_121331_created_date_index;
mod m20250429_142011_add_identifier;
mod m20250502_075301_did_identifier;
mod m20250502_114600_add_deleted_at_to_identifier;
mod m20250508_072524_change_enum_to_varchar;
mod m20250508_143325_remove_credential_did_relation;
mod m20250509_092249_reapply_not_null_constraint_on_enum_columns;
mod m20250509_113851_change_enum_to_varchar_history_entity_type;
mod m20250512_075017_remove_proof_did_relation;
mod m20250512_110852_certificate;
mod m20250513_075017_rename_identifier_status_to_state;
mod m20250526_112527_proof_verifier_certificate;
mod m20250526_125848_add_certificate_id_to_credential;
mod m20250528_101308_certificate_fingerprint;
mod m20250602_054912_add_organization_id_to_certificate;
mod m20250605_085443_add_identifier_id_field_to_revocation_list;
mod m20250605_085900_populate_identifier_id_column_in_revocation_list;
mod m20250605_092053_drop_column_issuer_did_id_in_revocation_list;
mod m20250607_093448_history_optional_orgid;
mod m20250608_142503_remove_did_mdl;
mod m20250611_110354_trust_entity_remove_did_add_org_type_content_entitykey;
mod m20250613_090205_fix_did_did_org_unique_index;
mod m20250613_105410_add_did_did_index;
mod m20250616_053001_remove_sd_jwt_vc_issuer_metadata;
mod m20250616_054713_add_x509_crl_remote_entity_type;
mod m20250617_055001_forbid_id_claim_name_jwt_formats;
mod m20250619_083023_name_deleted_at_unique;
mod m20250620_123138_simplify_trust_entity_entity_key_index;
mod m20250624_093010_rename_exchange_to_protocol;
mod m20250624_112336_add_deactivated_at_to_organisation;
mod m20250630_144901_add_expiry_to_remote_entity_cache;
mod m20250708_110608_credential_list_indexes;
mod m20250709_133731_key_reference_nullable;
mod m20250710_065056_cache_clear_by_last_used;
mod m20250721_075026_add_profile_field_credentials_proofs;
mod m20250721_102954_creation_of_blob_storage;
mod m20250722_120301_credential_blob_separation;
mod m20250728_090404_did_key_reference;
mod m20250729_114143_proof_blob;
mod m20250729_132707_issuance_date_nullable;
mod m20250730_090958_drop_proof_issuance_date;
mod m20250807_141417_blob_storage_foreign_key_relations;
mod m20250807_144007_make_claim_values_nullable;
mod m20250811_154134_insert_container_claims;
mod m20250814_120106_add_selectively_disclosable_column_to_claims;
mod m20250818_045324_json_ld_bbs_disclosability;
mod m20250818_082108_mdoc_disclosability;
mod m20250818_090154_set_selectively_disclosable_on_sd_jwt_claims;
mod m20250820_084021_wallet_unit_table;
mod m20250822_091700_add_wallet_unit_attestation_table;
mod m20250822_112457_add_metadata_claim_schema_column;
mod m20250822_122340_update_wallet_unit_table;
mod m20250826_081725_update_wallet_unit_attestation_expiration_date_not_nullable;
mod m20250901_114033_wua_last_modified_issued_nullability;
mod m20250902_121056_adds_engagement_column_to_proof;
mod m20250904_111452_wallet_unit_nullable_pubkey;
mod m20250911_133704_add_org_to_wallet_unit;
mod m20250911_140445_add_wallet_unit_provider_config_to_org;
mod m20250916_140953_add_metadata_index_to_history;
mod m20250919_095358_nonce_id;
mod m20250922_102649_adds_user_column_to_history;
mod m20251001_103610_adds_wua_column_to_credential;
mod m20251014_101039_adds_interaction_type;
mod m20251015_091929_drop_interaction_host;
mod m20251017_074815_fix_undefined_interaction_type;
mod m20251023_073646_drop_credential_schema_type_and_external_columns;
mod m20251027_101749_add_wallet_unit_attested_key;
mod m20251029_144801_add_holder_wallet_unit;
mod m20251030_110836_revocation_list_entry;
mod m20251103_093028_attested_key_revocation;
mod m20251103_141414_add_credential_schema_requires_app_attestation_column;
mod m20251105_103659_add_remote_entity_storage_indices;
mod m20251105_121212_waa_and_wua_blobs;
mod m20251110_130252_migrate_storage_type;
mod m20251112_152945_remote_entity_type;
mod m20251114_085246_remove_credential_schema_claim_schema_table;
mod m20251114_092439_drop_holder_identifier_column_from_proof;
mod m20251124_055356_revocation_list_unique;
mod m20251125_104708_history_source;
mod m20251126_134434_add_history_created_date_index;
mod m20251127_092659_add_drop_wallet_unit_attestation_history;
mod m20251127_162310_add_org_created_history_idx;
mod m20251128_080107_credential_columns_not_null;
mod m20251201_091341_remove_default_org_type;
mod m20251205_094417_align_history;
mod m20251208_141548_add_columns_is_active_and_type_to_revocation_entry;
mod m20251215_095000_add_signaturetype_column_to_revocation_entry;
mod m20251219_033012_claim_table;
mod m20251219_043510_credential_schema_table;
mod m20251219_062738_claim_schema_table;
mod m20251219_071908_certificate_table;
mod m20251219_082217_did_table;
mod migrate_enum;

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
            Box::new(m20240319_105859_typed_credential_schema::Migration),
            Box::new(m20240321_154846_add_layout_type_and_layout_properties_to_credential_schema::Migration),
            Box::new(m20240424_124450_add_json_ld_context::Migration),
            Box::new(m20240514_070446_add_trust_model::Migration),
            Box::new(m20240522_081021_fix_trust_priority_type::Migration),
            Box::new(m20240522_093357_add_errored_variant_to_history_action_enum_in_history_table::Migration),
            Box::new(m20240523_093449_add_cascade_to_trust_entity_fk::Migration),
            Box::new(m20240528_090016_rename_lvvc_table_to_validity_credential::Migration),
            Box::new(m20240528_092240_add_type_field_to_validity_credential_table::Migration),
            Box::new(m20240528_093449_make_trust_columns_optional::Migration),
            Box::new(m20240528_120000_add_shared_imported_history_action::Migration),
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
            Box::new(m20241031_095859_redirect_uri_length::Migration),
            Box::new(m20241101_092048_clear_statuslist_cache::Migration),
            Box::new(m20241104_085435_rename_sdjwt_with_underscore::Migration),
            Box::new(m20241119_071036_add_revocation_format_type::Migration),
            Box::new(m20241119_095859_redirect_uri_length::Migration),
            Box::new(m20241115_090000_add_media_type_to_remote_entity::Migration),
            Box::new(m20241120_164124_update_trust_anchor_and_entity_tables::Migration),
            Box::new(m20241125_170909_trust_anchor_publisher_reference_mandatory::Migration),
            Box::new(m20241126_105830_drop_reactivated_history_action::Migration),
            Box::new(m20241127_112144_did_organisation_id_optional::Migration),
            Box::new(m20241126_154001_update_remote_entity_type_enum_in_remote_entity_cache_table::Migration),
            Box::new(m20241203_08000_update_remote_entity_type_enum_trust_list::Migration),
            Box::new(m20241224_08000_fix_index_for_credential_schema::Migration),
            Box::new(m20241218_134714_history_entity_id_index::Migration),
            Box::new(m20241210_154315_remove_proof_state_table::Migration),
            Box::new(m20241212_08000_migrate_credential_state::Migration),
            Box::new(m20250107_134349_did_sd_jwt_vc_issuer_metadata::Migration),
            Box::new(m20250113_115815_trust_entity_unique_did::Migration),
            Box::new(m20250117_085705_remove_state_tables::Migration),
            Box::new(m20250124_152249_update_status_list_enum_variant_in_remote_entity_type_table::Migration),
            Box::new(m20250203_143642_add_rse_storage_type::Migration),
            Box::new(m20250205_120540_rename_bitstring_status_list_type_in_revocation_list_table::Migration),
            Box::new(m20250214_102249_missing_remote_entity_type::Migration),
            Box::new(m20250218_094713_add_trust_entity_history_changes::Migration),
            Box::new(m20250218_161915_add_proof_role::Migration),
            Box::new(m20250220_131625_add_proof_state_retracted::Migration),
            Box::new(m20250220_080800_add_external_credential_schema_flag::Migration),
            Box::new(m20250314_114529_rename_transport_to_exchange::Migration),
            Box::new(m20250317_133346_add_org_name::Migration),
            Box::new(m20250319_101601_add_updated_history_action::Migration),
            Box::new(m20250327_141601_add_new_history_action::Migration),
            Box::new(m20250324_150815_add_name_to_history_table::Migration),
            Box::new(m20250331_143210_rename_es256_to_ecdsa::Migration),
            Box::new(m20250331_115152_add_history_target::Migration),
            Box::new(m20250401_140204_add_reactivated_history_enum::Migration),
            Box::new(m20250403_083609_exchange_rename::Migration),
            Box::new(m20250401_110914_add_log_column_to_did_table::Migration),
            Box::new(m20250414_111854_add_update_key_enum_to_key_did::Migration),
            Box::new(m20250426_093351_large_blob::Migration),
            Box::new(m20250429_121331_created_date_index::Migration),
            Box::new(m20250429_142011_add_identifier::Migration),
            Box::new(m20250502_114600_add_deleted_at_to_identifier::Migration),
            Box::new(m20250502_075301_did_identifier::Migration),
            Box::new(m20250508_072524_change_enum_to_varchar::Migration),
            Box::new(m20250509_092249_reapply_not_null_constraint_on_enum_columns::Migration),
            Box::new(m20250508_143325_remove_credential_did_relation::Migration),
            Box::new(m20250509_113851_change_enum_to_varchar_history_entity_type::Migration),
            Box::new(m20250512_075017_remove_proof_did_relation::Migration),
            Box::new(m20250512_110852_certificate::Migration),
            Box::new(m20250513_075017_rename_identifier_status_to_state::Migration),
            Box::new(m20250526_112527_proof_verifier_certificate::Migration),
            Box::new(m20250526_125848_add_certificate_id_to_credential::Migration),
            Box::new(m20250528_101308_certificate_fingerprint::Migration),
            Box::new(m20250602_054912_add_organization_id_to_certificate::Migration),
            Box::new(m20250607_093448_history_optional_orgid::Migration),
            Box::new(m20250605_085443_add_identifier_id_field_to_revocation_list::Migration),
            Box::new(m20250605_085900_populate_identifier_id_column_in_revocation_list::Migration),
            Box::new(m20250605_092053_drop_column_issuer_did_id_in_revocation_list::Migration),
            Box::new(m20250608_142503_remove_did_mdl::Migration),
            Box::new(m20250613_090205_fix_did_did_org_unique_index::Migration),
            Box::new(m20250611_110354_trust_entity_remove_did_add_org_type_content_entitykey::Migration),
            Box::new(m20250613_105410_add_did_did_index::Migration),
            Box::new(m20250616_053001_remove_sd_jwt_vc_issuer_metadata::Migration),
            Box::new(m20250616_054713_add_x509_crl_remote_entity_type::Migration),
            Box::new(m20250617_055001_forbid_id_claim_name_jwt_formats::Migration),
            Box::new(m20250619_083023_name_deleted_at_unique::Migration),
            Box::new(m20250620_123138_simplify_trust_entity_entity_key_index::Migration),
            Box::new(m20250624_093010_rename_exchange_to_protocol::Migration),
            Box::new(m20250624_112336_add_deactivated_at_to_organisation::Migration),
            Box::new(m20250630_144901_add_expiry_to_remote_entity_cache::Migration),
            Box::new(m20250708_110608_credential_list_indexes::Migration),
            Box::new(m20250709_133731_key_reference_nullable::Migration),
            Box::new(m20250710_065056_cache_clear_by_last_used::Migration),
            Box::new(m20250721_075026_add_profile_field_credentials_proofs::Migration),
            Box::new(m20250721_102954_creation_of_blob_storage::Migration),
            Box::new(m20250728_090404_did_key_reference::Migration),
            Box::new(m20250722_120301_credential_blob_separation::Migration),
            Box::new(m20250729_132707_issuance_date_nullable::Migration),
            Box::new(m20250730_090958_drop_proof_issuance_date::Migration),
            Box::new(m20250729_114143_proof_blob::Migration),
            Box::new(m20250807_144007_make_claim_values_nullable::Migration),
            Box::new(m20250807_141417_blob_storage_foreign_key_relations::Migration),
            Box::new(m20250811_154134_insert_container_claims::Migration),
            Box::new(m20250814_120106_add_selectively_disclosable_column_to_claims::Migration),
            Box::new(m20250818_045324_json_ld_bbs_disclosability::Migration),
            Box::new(m20250818_082108_mdoc_disclosability::Migration),
            Box::new(m20250818_090154_set_selectively_disclosable_on_sd_jwt_claims::Migration),
            Box::new(m20250820_084021_wallet_unit_table::Migration),
            Box::new(m20250822_112457_add_metadata_claim_schema_column::Migration),
            Box::new(m20250822_091700_add_wallet_unit_attestation_table::Migration),
            Box::new(m20250822_122340_update_wallet_unit_table::Migration),
            Box::new(m20250826_081725_update_wallet_unit_attestation_expiration_date_not_nullable::Migration),
            Box::new(m20250901_114033_wua_last_modified_issued_nullability::Migration),
            Box::new(m20250902_121056_adds_engagement_column_to_proof::Migration),
            Box::new(m20250904_111452_wallet_unit_nullable_pubkey::Migration),
            Box::new(m20250911_133704_add_org_to_wallet_unit::Migration),
            Box::new(m20250911_140445_add_wallet_unit_provider_config_to_org::Migration),
            Box::new(m20250916_140953_add_metadata_index_to_history::Migration),
            Box::new(m20250919_095358_nonce_id::Migration),
            Box::new(m20250922_102649_adds_user_column_to_history::Migration),
            Box::new(m20251001_103610_adds_wua_column_to_credential::Migration),
            Box::new(m20251014_101039_adds_interaction_type::Migration),
            Box::new(m20251015_091929_drop_interaction_host::Migration),
            Box::new(m20251017_074815_fix_undefined_interaction_type::Migration),
            Box::new(m20251023_073646_drop_credential_schema_type_and_external_columns::Migration),
            Box::new(m20251027_101749_add_wallet_unit_attested_key::Migration),
            Box::new(m20251029_144801_add_holder_wallet_unit::Migration),
            Box::new(m20251030_110836_revocation_list_entry::Migration),
            Box::new(m20251103_093028_attested_key_revocation::Migration),
            Box::new(m20251103_141414_add_credential_schema_requires_app_attestation_column::Migration),
            Box::new(m20251105_121212_waa_and_wua_blobs::Migration),
            Box::new(m20251105_103659_add_remote_entity_storage_indices::Migration),
            Box::new(m20251112_152945_remote_entity_type::Migration),
            Box::new(m20251114_085246_remove_credential_schema_claim_schema_table::Migration),
            Box::new(m20251110_130252_migrate_storage_type::Migration),
            Box::new(m20251114_092439_drop_holder_identifier_column_from_proof::Migration),
            Box::new(m20251124_055356_revocation_list_unique::Migration),
            Box::new(m20251125_104708_history_source::Migration),
            Box::new(m20251126_134434_add_history_created_date_index::Migration),
            Box::new(m20251127_092659_add_drop_wallet_unit_attestation_history::Migration),
            Box::new(m20251127_162310_add_org_created_history_idx::Migration),
            Box::new(m20251128_080107_credential_columns_not_null::Migration),
            Box::new(m20251201_091341_remove_default_org_type::Migration),
            Box::new(m20251205_094417_align_history::Migration),
            Box::new(m20251208_141548_add_columns_is_active_and_type_to_revocation_entry::Migration),
            Box::new(m20251215_095000_add_signaturetype_column_to_revocation_entry::Migration),
            Box::new(m20251219_033012_claim_table::Migration),
            Box::new(m20251219_043510_credential_schema_table::Migration),
            Box::new(m20251219_062738_claim_schema_table::Migration),
            Box::new(m20251219_071908_certificate_table::Migration),
            Box::new(m20251219_082217_did_table::Migration),
        ]
    }
}
