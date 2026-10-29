use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{integer, integer_null, string};

use crate::datatype::{large_blob, timestamp, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{Certificate, Identifier};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db_type = manager.supported_db_type();
        if db_type == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(RevocationList::Table)
                        .add_column(integer_null(RevocationList::SequenceNumber))
                        .to_owned(),
                )
                .await?;
            manager
                .exec_stmt(
                    Query::update()
                        .table(RevocationList::Table)
                        .value(RevocationList::SequenceNumber, 0)
                        .to_owned(),
                )
                .await?;
            manager
                .alter_table(
                    Table::alter()
                        .table(RevocationList::Table)
                        .modify_column(integer(RevocationList::SequenceNumber))
                        .to_owned(),
                )
                .await?;
        }

        // The new index is created before the old one is dropped:
        // MariaDB refuses to drop the index backing the issuer identifier foreign key
        add_nullable_unique_idx(
            RevocationList::Table,
            RevocationList::IssuerCertificateId,
            "index-RevocationList-Issuer-Purpose-Type-SequenceNumber-Unique",
            NullableIdxOpts {
                non_nullable_columns: vec![
                    RevocationList::IssuerIdentifierId,
                    RevocationList::Purpose,
                    RevocationList::Type,
                    RevocationList::SequenceNumber,
                ],
                null_value: Some("no_certificate"),
                nullable_column_index_pos: Some(1),
                materialized_column_size_limit: Some(36),
            },
            manager,
        )
        .await?;

        let mut index_drop = Index::drop()
            .name("index-IssuerIdentifierId-IssuerCertificateId-Purpose-Type-Unique")
            .table(RevocationList::Table)
            .to_owned();
        // Mysql does not support IF EXISTS for DROP INDEX
        if db_type != SupportedDbType::MySql {
            index_drop.if_exists();
        }
        manager.drop_index(index_drop).await?;

        Ok(())
    }
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    disable_foreign_key_checks(manager).await?;

    manager
        .create_table(
            Table::create()
                .table(RevocationListNew::Table)
                .col(uuid_char(RevocationList::Id).primary_key())
                .col(timestamp(RevocationList::CreatedDate, manager))
                .col(timestamp(RevocationList::LastModified, manager))
                .col(large_blob(RevocationList::FormattedList, manager))
                .col(string(RevocationList::Purpose))
                .col(string(RevocationList::Format))
                .col(string(RevocationList::Type))
                .col(uuid_char(RevocationList::IssuerIdentifierId))
                .col(uuid_char_null(RevocationList::IssuerCertificateId))
                .col(integer(RevocationList::SequenceNumber))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_revocation_list_issuer_identifier_id")
                        .from_tbl(RevocationListNew::Table)
                        .from_col(RevocationList::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_revocation_list_issuer_certificate_id")
                        .from_tbl(RevocationListNew::Table)
                        .from_col(RevocationList::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        RevocationList::Id,
        RevocationList::CreatedDate,
        RevocationList::LastModified,
        RevocationList::FormattedList,
        RevocationList::Purpose,
        RevocationList::Format,
        RevocationList::Type,
        RevocationList::IssuerIdentifierId,
        RevocationList::IssuerCertificateId,
    ];
    let mut insert_columns = copied_columns.clone();
    insert_columns.push(RevocationList::SequenceNumber);
    manager
        .exec_stmt(
            Query::insert()
                .into_table(RevocationListNew::Table)
                .columns(insert_columns)
                .select_from(
                    Query::select()
                        .from(RevocationList::Table)
                        .columns(copied_columns)
                        .expr(Expr::value(0))
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(RevocationList::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(RevocationListNew::Table, RevocationList::Table)
                .to_owned(),
        )
        .await?;

    enable_foreign_key_checks(manager).await
}

#[derive(Clone, DeriveIden)]
enum RevocationList {
    Table,
    Id,
    CreatedDate,
    LastModified,
    FormattedList,
    Purpose,
    Format,
    Type,
    IssuerIdentifierId,
    IssuerCertificateId,
    SequenceNumber,
}

#[derive(DeriveIden)]
enum RevocationListNew {
    Table,
}
