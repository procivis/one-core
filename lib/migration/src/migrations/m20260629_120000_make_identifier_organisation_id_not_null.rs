use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{Did, Identifier, Key, Organisation};
use crate::nullable_unique_idx::{NullableIdxOpts, add_nullable_unique_idx};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

// Mirrors the constants defined (privately) in m20260417_150300_initial for the identifier table.
const FK_IDENTIFIER_ORGANISATION: &str = "fk_identifier_organisation";
const FK_IDENTIFIER_DID: &str = "fk_identifier_did";
const FK_IDENTIFIER_KEY: &str = "fk_identifier_key";
const INDEX_UNIQUE_IDENTIFIER_NAME_ORGANISATION_DELETED_AT: &str =
    "index_Identifier_Name-OrganisationId-DeletedAt_Unique";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        disable_foreign_key_checks(manager).await?;

        // All the identifiers without organisation are an artifact of the legacy trust management.
        // These are identifiers belonging to verifier installations that enrolled themselves onto the
        // legacy trust lists. Given the legacy trust management has been removed, the identifiers are no longer needed.
        // And since they have not been associated with any organisation, they should not have been
        // used for other purposes since.
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Identifier::Table)
                    .and_where(Expr::col(Identifier::OrganisationId).is_null())
                    .to_owned(),
            )
            .await?;

        if manager.supported_db_type() == SupportedDbType::Sqlite {
            self.up_sqlite(manager).await?;
        } else {
            self.up_sane(manager).await?;
        }

        enable_foreign_key_checks(manager).await?;
        Ok(())
    }
}

impl Migration {
    async fn up_sane(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Identifier::Table)
                    .modify_column(uuid_char(Identifier::OrganisationId))
                    .to_owned(),
            )
            .await
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(IdentifierNew::Table)
                    .col(uuid_char(Identifier::Id).primary_key())
                    .col(timestamp(Identifier::CreatedDate, manager))
                    .col(timestamp(Identifier::LastModified, manager))
                    .col(timestamp_null(Identifier::DeletedAt, manager))
                    .col(string(Identifier::Name))
                    .col(string(Identifier::Type))
                    .col(boolean(Identifier::IsRemote))
                    .col(string(Identifier::State))
                    .col(uuid_char(Identifier::OrganisationId))
                    .col(uuid_char_null(Identifier::DidId))
                    .col(uuid_char_null(Identifier::KeyId))
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name(FK_IDENTIFIER_ORGANISATION)
                            .from_tbl(IdentifierNew::Table)
                            .from_col(Identifier::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name(FK_IDENTIFIER_DID)
                            .from_tbl(IdentifierNew::Table)
                            .from_col(Identifier::DidId)
                            .to_tbl(Did::Table)
                            .to_col(Did::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name(FK_IDENTIFIER_KEY)
                            .from_tbl(IdentifierNew::Table)
                            .from_col(Identifier::KeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id),
                    )
                    .to_owned(),
            )
            .await?;

        let copied_columns = vec![
            Identifier::Id,
            Identifier::CreatedDate,
            Identifier::LastModified,
            Identifier::DeletedAt,
            Identifier::Name,
            Identifier::Type,
            Identifier::IsRemote,
            Identifier::State,
            Identifier::OrganisationId,
            Identifier::DidId,
            Identifier::KeyId,
        ];
        manager
            .exec_stmt(
                Query::insert()
                    .into_table(IdentifierNew::Table)
                    .columns(copied_columns.clone())
                    .select_from(
                        Query::select()
                            .columns(copied_columns)
                            .from(Identifier::Table)
                            .to_owned(),
                    )
                    .map_err(|e| DbErr::Migration(e.to_string()))?
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(Identifier::Table).to_owned())
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(IdentifierNew::Table, Identifier::Table)
                    .to_owned(),
            )
            .await?;

        add_nullable_unique_idx(
            Identifier::Table,
            Identifier::DeletedAt,
            INDEX_UNIQUE_IDENTIFIER_NAME_ORGANISATION_DELETED_AT,
            NullableIdxOpts {
                non_nullable_columns: vec![Identifier::Name, Identifier::OrganisationId],
                ..Default::default()
            },
            manager,
        )
        .await?;
        Ok(())
    }
}

#[derive(DeriveIden)]
enum IdentifierNew {
    Table,
}
