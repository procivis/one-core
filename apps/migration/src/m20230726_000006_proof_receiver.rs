use sea_orm_migration::{prelude::*, sea_orm::DbBackend};

use crate::{m20230530_000001_initial::ProofSchema, m20230707_000004_add_credential::Did};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            sea_orm::DatabaseBackend::Sqlite => up_sqlite(manager).await,
            _ => up_other(manager).await,
        }
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() == DbBackend::Sqlite {
            unimplemented!()
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Proof::Table)
                        .drop_foreign_key(Alias::new("fk-Proof-ReceiverDidId"))
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Proof::Table)
                        .drop_column(Proof::ReceiverDidId)
                        .to_owned(),
                )
                .await?;

            Ok(())
        }
    }
}

#[allow(dead_code)]
#[derive(Iden)]
pub enum Proof {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DidId,
    ReceiverDidId,
    ProofSchemaId,
}

async fn up_sqlite<'a>(manager: &'a SchemaManager<'a>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("proof_new"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Proof::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Proof::CreatedDate).date_time().not_null())
                .col(ColumnDef::new(Proof::LastModified).date_time().not_null())
                .col(ColumnDef::new(Proof::IssuanceDate).date_time().not_null())
                .col(ColumnDef::new(Proof::DidId).string().not_null())
                .col(ColumnDef::new(Proof::ReceiverDidId).string())
                .col(ColumnDef::new(Proof::ProofSchemaId).char_len(36).not_null())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-DidId")
                        .from_tbl(Proof::Table)
                        .from_col(Proof::DidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-ReceiverDidId")
                        .from_tbl(Proof::Table)
                        .from_col(Proof::ReceiverDidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-ProofSchemaId")
                        .from_tbl(Proof::Table)
                        .from_col(Proof::ProofSchemaId)
                        .to_tbl(ProofSchema::Table)
                        .to_col(ProofSchema::Id),
                )
                .to_owned(),
        )
        .await?;

    let db = manager.get_connection();
    db.execute_unprepared("INSERT INTO \
        proof_new(id,created_date,last_modified,issuance_date,did_id,receiver_did_id,proof_schema_id) \
        SELECT id,created_date,last_modified,issuance_date,did_id,NULL,proof_schema_id \
        FROM proof")
        .await?;

    manager
        .drop_table(Table::drop().table(Proof::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(Alias::new("proof_new"), Proof::Table)
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn up_other<'a>(manager: &'a SchemaManager<'a>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Proof::Table)
                .add_column(ColumnDef::new(Proof::ReceiverDidId).string())
                .add_foreign_key(
                    TableForeignKey::new()
                        .name("fk-Proof-ReceiverDidId")
                        .from_tbl(Proof::Table)
                        .from_col(Proof::ReceiverDidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}
