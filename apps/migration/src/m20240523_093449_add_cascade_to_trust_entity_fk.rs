use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::CustomDateTime;
use crate::m20240209_144950_add_verifier_key_id_to_proof::{
    copy_data_to_new_tables, drop_and_rename_tables,
};
use crate::m20240514_070446_add_trust_model::{TrustAnchor, TrustEntity, TrustEntityRole};

#[derive(DeriveMigrationName)]
pub struct Migration;

const UNIQUE_TRUST_ENTITY_ENTITY_ID_IN_ANCHOR: &str =
    "index-TrustEntityNew-EntityId-TrustAnchorId-Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let datetime = CustomDateTime(manager.get_database_backend());

        manager
            .create_table(
                Table::create()
                    .table(TrustEntityNew::Table)
                    .col(
                        ColumnDef::new(TrustEntityNew::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(TrustEntityNew::CreatedDate)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustEntityNew::LastModified)
                            .custom(datetime)
                            .not_null(),
                    )
                    .col(ColumnDef::new(TrustEntityNew::EntityId).string().not_null())
                    .col(ColumnDef::new(TrustEntityNew::Name).string().not_null())
                    .col(ColumnDef::new(TrustEntityNew::Logo).string())
                    .col(ColumnDef::new(TrustEntityNew::Website).string())
                    .col(ColumnDef::new(TrustEntityNew::TermsUrl).string())
                    .col(ColumnDef::new(TrustEntityNew::PrivacyUrl).string())
                    .col(
                        ColumnDef::new(TrustEntityNew::Role)
                            .enumeration(
                                TrustEntityRole::Table,
                                [
                                    TrustEntityRole::Issuer,
                                    TrustEntityRole::Verifier,
                                    TrustEntityRole::Both,
                                ],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(TrustEntityNew::TrustAnchorId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-TrustEntityNew-TrustAnchorId")
                            .from_tbl(TrustEntityNew::Table)
                            .from_col(TrustEntityNew::TrustAnchorId)
                            .to_tbl(TrustAnchor::Table)
                            .to_col(TrustAnchor::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name(UNIQUE_TRUST_ENTITY_ENTITY_ID_IN_ANCHOR)
                    .table(TrustEntityNew::Table)
                    .col(TrustEntityNew::EntityId)
                    .col(TrustEntityNew::TrustAnchorId)
                    .unique()
                    .to_owned(),
            )
            .await?;

        let db = manager.get_connection();
        copy_data_to_new_tables(db, vec![("trust_entity", "trust_entity_new")]).await?;
        drop_and_rename_tables(
            manager,
            vec![(
                TrustEntity::Table.into_table_ref(),
                TrustEntityNew::Table.into_table_ref(),
            )],
        )
        .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum TrustEntityNew {
    Table,
    Id,
    CreatedDate,
    LastModified,
    EntityId,
    Name,
    Logo,
    Website,
    TermsUrl,
    PrivacyUrl,
    Role,
    TrustAnchorId,
}
