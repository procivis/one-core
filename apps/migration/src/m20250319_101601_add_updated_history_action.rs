use sea_orm::EnumIter;
use sea_orm_migration::prelude::*;

use crate::migrate_enum::add_enum_variant;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        add_enum_variant::<UpdatedHistoryAction>(manager, "history", "action").await
    }
}

#[derive(Iden, EnumIter)]
pub enum UpdatedHistoryAction {
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "CREATED"]
    Created,
    #[iden = "DEACTIVATED"]
    Deactivated,
    #[iden = "DELETED"]
    Deleted,
    #[iden = "ERRORED"]
    Errored,
    #[iden = "ISSUED"]
    Issued,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REQUESTED"]
    Requested,
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "PENDING"]
    Pending,
    #[iden = "SUSPENDED"]
    Suspended,
    #[iden = "RESTORED"]
    Restored,
    #[iden = "SHARED"]
    Shared,
    #[iden = "IMPORTED"]
    Imported,
    #[iden = "CLAIMS_REMOVED"]
    ClaimsRemoved,
    #[iden = "ACTIVATED"]
    Activated,
    #[iden = "WITHDRAWN"]
    Withdrawn,
    #[iden = "REMOVED"]
    Removed,
    #[iden = "RETRACTED"]
    Retracted,
    #[iden = "UPDATED"]
    Updated,
}
