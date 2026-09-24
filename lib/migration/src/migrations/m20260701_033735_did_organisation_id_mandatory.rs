use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, string_len, text_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{Did, Organisation};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Did::Table)
                    .and_where(Expr::col(Did::OrganisationId).is_null())
                    .to_owned(),
            )
            .await?;

        disable_foreign_key_checks(manager).await?;

        let backend = manager.supported_db_type();
        if backend == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            manager
                .drop_index(
                    Index::drop()
                        .name("index-Did-Did-OrganisationId-DeletedAt-Unique")
                        .table(Did::Table)
                        .to_owned(),
                )
                .await?;

            if backend == SupportedDbType::MySql {
                manager
                    .alter_table(
                        Table::alter()
                            .table(Did::Table)
                            .drop_column("organisation_id_materialized")
                            .to_owned(),
                    )
                    .await?;
            }

            manager
                .alter_table(
                    Table::alter()
                        .table(Did::Table)
                        .modify_column(uuid_char(Did::OrganisationId))
                        .to_owned(),
                )
                .await?;
        }

        enable_foreign_key_checks(manager).await?;

        add_nullable_unique_idx(
            Did::Table,
            Did::DeletedAt,
            "index-Did-Did-OrganisationId-DeletedAt-Unique",
            NullableIdxOpts {
                non_nullable_columns: vec![Did::Did, Did::OrganisationId],
                ..Default::default()
            },
            manager,
        )
        .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum DidNew {
    Table,
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(DidNew::Table)
                .col(uuid_char(Did::Id).primary_key())
                .col(timestamp(Did::CreatedDate, manager))
                .col(timestamp(Did::LastModified, manager))
                .col(timestamp_null(Did::DeletedAt, manager))
                .col(string_len(Did::Did, 4000))
                .col(string(Did::Name))
                .col(string(Did::Type))
                .col(string(Did::Method))
                .col(boolean(Did::Deactivated))
                .col(text_null(Did::Log))
                .col(uuid_char(Did::OrganisationId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-Did-OrganisationId")
                        .from_tbl(Did::Table)
                        .from_col(Did::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        Did::Id,
        Did::Did,
        Did::CreatedDate,
        Did::LastModified,
        Did::Name,
        Did::Type,
        Did::Method,
        Did::OrganisationId,
        Did::Deactivated,
        Did::DeletedAt,
        Did::Log,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(DidNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(Did::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Did::Table).to_owned())
        .await?;

    manager
        .rename_table(Table::rename().table(DidNew::Table, Did::Table).to_owned())
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Did-CreatedDate")
                .table(Did::Table)
                .col(Did::CreatedDate)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Did-Did")
                .table(Did::Table)
                .col(Did::Did)
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        Did::Table,
        Did::DeletedAt,
        "index_Did_Name-OrganisationId-DeletedAt_Unique",
        NullableIdxOpts {
            non_nullable_columns: vec![Did::Name, Did::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await?;

    Ok(())
}
