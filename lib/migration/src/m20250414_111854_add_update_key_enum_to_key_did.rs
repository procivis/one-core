use sea_orm::EnumIter;
use sea_orm_migration::prelude::*;

use crate::migrate_enum::add_enum_variant;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
