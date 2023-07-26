use sea_orm_migration::{prelude::*, sea_orm::DbBackend};

use crate::{
    m20230530_000001_initial::CredentialSchema,
    m20230707_000004_add_credential::{Did, Transport},
};

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
                        .table(Credential::Table)
                        .drop_foreign_key(Alias::new("fk-Credential-ReceiverDidId"))
                        .to_owned(),
                )
                .await?;

            manager
                .alter_table(
                    Table::alter()
                        .table(Credential::Table)
                        .drop_column(Credential::ReceiverDidId)
                        .to_owned(),
                )
                .await?;

            manager
                .drop_index(
                    Index::drop()
                        .name("index-Did-Did-Unique")
                        .table(Did::Table)
                        .to_owned(),
                )
                .await?;

            Ok(())
        }
    }
}

#[allow(dead_code)]
#[derive(Iden)]
pub enum Credential {
    Table,
    Id,
    CreatedDate,
    LastModified,
    IssuanceDate,
    DeletedAt,
    Transport,
    Credential,
    CredentialSchemaId,
    DidId,
    ReceiverDidId,
}

async fn up_sqlite<'a>(manager: &'a SchemaManager<'a>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Alias::new("credential_new"))
                .if_not_exists()
                .col(
                    ColumnDef::new(Credential::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Credential::CreatedDate)
                        .date_time()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Credential::LastModified)
                        .date_time()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Credential::IssuanceDate)
                        .date_time()
                        .not_null(),
                )
                .col(ColumnDef::new(Credential::DeletedAt).date_time().null())
                .col(
                    ColumnDef::new(Credential::Transport)
                        .enumeration(
                            Transport::Table,
                            [Transport::ProcivisTemporary, Transport::OpenId4Vc],
                        )
                        .not_null(),
                )
                .col(ColumnDef::new(Credential::Credential).binary().not_null())
                .col(
                    ColumnDef::new(Credential::CredentialSchemaId)
                        .char_len(36)
                        .not_null(),
                )
                .col(ColumnDef::new(Credential::DidId).string())
                .col(ColumnDef::new(Credential::ReceiverDidId).string())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-CredentialSchemaId")
                        .from_tbl(Credential::Table)
                        .from_col(Credential::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-DidId")
                        .from_tbl(Credential::Table)
                        .from_col(Credential::DidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Credential-ReceiverDidId")
                        .from_tbl(Credential::Table)
                        .from_col(Credential::ReceiverDidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .to_owned(),
        )
        .await?;

    let db = manager.get_connection();
    db.execute_unprepared("INSERT INTO \
        credential_new(id,created_date,last_modified,issuance_date,deleted_at,transport,credential,credential_schema_id,did_id,receiver_did_id) \
        SELECT id,created_date,last_modified,issuance_date,deleted_at,transport,credential,credential_schema_id,did_id,NULL \
        FROM credential")
        .await?;

    manager
        .drop_table(Table::drop().table(Credential::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(Alias::new("credential_new"), Credential::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("index-Did-Did-Unique")
                .unique()
                .table(Did::Table)
                .col(Did::Did)
                .to_owned(),
        )
        .await?;

    Ok(())
}

async fn up_other<'a>(manager: &'a SchemaManager<'a>) -> Result<(), DbErr> {
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name("index-Did-Did-Unique")
                .unique()
                .table(Did::Table)
                .col(Did::Did)
                .to_owned(),
        )
        .await?;

    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .add_foreign_key(
                    TableForeignKey::new()
                        .name("fk-Credential-ReceiverDidId")
                        .from_tbl(Credential::Table)
                        .from_col(Credential::ReceiverDidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .add_column(ColumnDef::new(Credential::ReceiverDidId).string())
                .to_owned(),
        )
        .await?;

    Ok(())
}
