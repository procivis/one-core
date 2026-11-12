use sea_orm_migration::prelude::*;
use sea_orm_migration_sqlite::{SchemaManagerExt, TableExt};

use crate::datatype::uuid_char;
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::Did;
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

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .recreate_table(
            Table::recreate()
                .table(Did::Table)
                .modify_column(uuid_char(Did::OrganisationId))
                .discard_indexes()
                .to_owned(),
        )
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
