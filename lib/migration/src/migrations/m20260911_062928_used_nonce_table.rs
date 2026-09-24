use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null};
use time::OffsetDateTime;

use crate::datatype::{large_blob_null, timestamp, timestamp_null, uuid_char};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{Interaction, Organisation};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(UsedNonce::Table)
                    .col(uuid_char(UsedNonce::Id).primary_key())
                    .col(timestamp(UsedNonce::CreatedDate, manager))
                    .col(uuid_char(UsedNonce::InteractionId))
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-UsedNonce-InteractionId")
                            .from_tbl(UsedNonce::Table)
                            .from_col(UsedNonce::InteractionId)
                            .to_tbl(Interaction::Table)
                            .to_col(Interaction::Id),
                    )
                    .to_owned(),
            )
            .await?;

        migrate_nonce_ids(manager).await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            cleanup_interaction_sqlite(manager).await?;
        } else {
            cleanup_interaction_simple(manager).await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum UsedNonce {
    Table,
    Id,
    CreatedDate,
    InteractionId,
}

async fn migrate_nonce_ids(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    #[derive(Clone, FromQueryResult)]
    struct InteractionResult {
        pub id: String,
        pub nonce_id: String,
    }

    let backend = manager.get_database_backend();
    let db = manager.get_connection();

    let interactions = InteractionResult::find_by_statement(
        backend.build(
            Query::select()
                .columns([Interaction::Id, Interaction::NonceId])
                .from(Interaction::Table)
                .cond_where(Expr::col(Interaction::NonceId).is_not_null()),
        ),
    )
    .all(db)
    .await?;

    let now = OffsetDateTime::now_utc();
    for (index, chunk) in interactions.chunks(1000).enumerate() {
        tracing::debug!(
            "Inserting nonces, chunk {index}/{}",
            interactions.len().div_ceil(1000)
        );

        let mut query = Query::insert()
            .into_table(UsedNonce::Table)
            .columns([
                UsedNonce::Id,
                UsedNonce::CreatedDate,
                UsedNonce::InteractionId,
            ])
            .to_owned();

        for interaction in chunk.iter().cloned() {
            query
                .values([
                    interaction.nonce_id.into(),
                    now.into(),
                    interaction.id.into(),
                ])
                .map_err(|e| DbErr::Migration(e.to_string()))?;
        }

        manager.exec_stmt(query).await?;
    }

    Ok(())
}

async fn cleanup_interaction_simple(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .drop_index(
            Index::drop()
                .name("index-Interaction-NonceId-Unique")
                .table(Interaction::Table)
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Interaction::Table)
                .drop_column(Interaction::NonceId)
                .to_owned(),
        )
        .await?;

    Ok(())
}

#[derive(DeriveIden)]
pub enum InteractionNew {
    Table,
    Ecosystem,
    EcosystemData,
}

async fn cleanup_interaction_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    disable_foreign_key_checks(manager).await?;

    manager
        .create_table(
            Table::create()
                .table(InteractionNew::Table)
                .col(uuid_char(Interaction::Id).primary_key())
                .col(timestamp(Interaction::CreatedDate, manager))
                .col(timestamp(Interaction::LastModified, manager))
                .col(timestamp_null(Interaction::ExpiresAt, manager))
                .col(large_blob_null(Interaction::Data, manager))
                .col(string(Interaction::InteractionType))
                .col(uuid_char(Interaction::OrganisationId))
                .col(string_null(InteractionNew::Ecosystem))
                .col(large_blob_null(InteractionNew::EcosystemData, manager))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-interaction-OrganisationId")
                        .from_tbl(Interaction::Table)
                        .from_col(Interaction::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        Interaction::Id.into_iden(),
        Interaction::CreatedDate.into_iden(),
        Interaction::LastModified.into_iden(),
        Interaction::ExpiresAt.into_iden(),
        Interaction::Data.into_iden(),
        Interaction::InteractionType.into_iden(),
        Interaction::OrganisationId.into_iden(),
        InteractionNew::Ecosystem.into_iden(),
        InteractionNew::EcosystemData.into_iden(),
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(InteractionNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(Interaction::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Interaction::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(InteractionNew::Table, Interaction::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Interaction-ExpiresAt")
                .table(Interaction::Table)
                .col(Interaction::ExpiresAt)
                .to_owned(),
        )
        .await?;

    enable_foreign_key_checks(manager).await?;

    Ok(())
}
