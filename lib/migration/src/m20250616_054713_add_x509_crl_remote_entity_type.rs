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
        add_enum_variant::<RemoteEntityType>(manager, "remote_entity_cache", "type").await
    }
}

#[derive(DeriveIden, EnumIter)]
pub enum RemoteEntityType {
    #[sea_orm(iden = "DID_DOCUMENT")]
    DidDocument,

    #[sea_orm(iden = "JSON_LD_CONTEXT")]
    JsonLdContext,

    #[sea_orm(iden = "STATUS_LIST_CREDENTIAL")]
    StatusListCredential,

    #[sea_orm(iden = "VCT_METADATA")]
    VctMetadata,

    #[sea_orm(iden = "JSON_SCHEMA")]
    JsonSchema,

    #[sea_orm(iden = "TRUST_LIST")]
    TrustList,

    #[sea_orm(iden = "X509_CRL")]
    X509Crl,
}
