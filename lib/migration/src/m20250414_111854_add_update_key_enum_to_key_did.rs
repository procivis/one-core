use sea_orm::EnumIter;
use sea_orm_migration::prelude::*;

use crate::migrate_enum::add_enum_variant;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == sea_orm::DatabaseBackend::Postgres {
            // Skip because it is not supported. If support for Postgres is added in the future
            // the schema can be setup in its entirety in a new, later migration.
            return Ok(());
        }
        add_enum_variant::<KeyRole>(manager, "key_did", "role").await
    }
}

#[derive(Iden, EnumIter)]
enum KeyRole {
    #[iden = "AUTHENTICATION"]
    Authentication,
    #[iden = "ASSERTION_METHOD"]
    AssertionMethod,
    #[iden = "KEY_AGREEMENT"]
    KeyAgreement,
    #[iden = "CAPABILITY_INVOCATION"]
    CapabilityInvocation,
    #[iden = "CAPABILITY_DELEGATION"]
    CapabilityDelegation,
    #[iden = "UPDATE_KEY"]
    UpdateKey,
}
