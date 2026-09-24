use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_null, text};

use crate::datatype::{timestamp, timestamp_null, timestamp_seconds, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{Certificate, Identifier, Key, Organisation};
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
                    .from_table(Certificate::Table)
                    .and_where(Expr::col(Certificate::OrganisationId).is_null())
                    .to_owned(),
            )
            .await?;

        disable_foreign_key_checks(manager).await?;

        let backend = manager.supported_db_type();
        if backend == SupportedDbType::Sqlite {
            up_sqlite(manager).await?;
        } else {
            manager
                .alter_table(
                    Table::alter()
                        .table(Certificate::Table)
                        .modify_column(uuid_char(Certificate::OrganisationId))
                        .to_owned(),
                )
                .await?;
        }

        enable_foreign_key_checks(manager).await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CertificateNew {
    Table,
}

async fn up_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CertificateNew::Table)
                .col(uuid_char(Certificate::Id).primary_key())
                .col(timestamp(Certificate::CreatedDate, manager))
                .col(timestamp(Certificate::LastModified, manager))
                .col(timestamp_null(Certificate::DeletedAt, manager))
                .col(timestamp_seconds(Certificate::ExpiryDate, manager))
                .col(string(Certificate::Name))
                .col(text(Certificate::Chain))
                .col(string(Certificate::Fingerprint))
                .col(string(Certificate::State))
                .col(string_null(Certificate::Roles))
                .col(uuid_char(Certificate::OrganisationId))
                .col(uuid_char(Certificate::IdentifierId))
                .col(uuid_char_null(Certificate::KeyId))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_certificate_organisation_id")
                        .from_tbl(Certificate::Table)
                        .from_col(Certificate::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_certificate_identifier")
                        .from_tbl(Certificate::Table)
                        .from_col(Certificate::IdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk_certificate_key")
                        .from_tbl(Certificate::Table)
                        .from_col(Certificate::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .to_owned(),
        )
        .await?;

    let copied_columns = vec![
        Certificate::Id,
        Certificate::CreatedDate,
        Certificate::LastModified,
        Certificate::DeletedAt,
        Certificate::ExpiryDate,
        Certificate::IdentifierId,
        Certificate::Name,
        Certificate::Chain,
        Certificate::State,
        Certificate::KeyId,
        Certificate::Fingerprint,
        Certificate::OrganisationId,
        Certificate::Roles,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(CertificateNew::Table)
                .columns(copied_columns.clone())
                .select_from(
                    Query::select()
                        .columns(copied_columns)
                        .from(Certificate::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Certificate::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CertificateNew::Table, Certificate::Table)
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("index-Certificate-Name-ExpiryDate-IdentifierId-Unique")
                .table(Certificate::Table)
                .col(Certificate::Name)
                .col(Certificate::ExpiryDate)
                .col(Certificate::IdentifierId)
                .unique()
                .to_owned(),
        )
        .await?;

    add_nullable_unique_idx(
        Certificate::Table,
        Certificate::DeletedAt,
        "index-Certificate-Fingerprint-OrganisationId-Unique",
        NullableIdxOpts {
            non_nullable_columns: vec![Certificate::Fingerprint, Certificate::OrganisationId],
            ..Default::default()
        },
        manager,
    )
    .await?;

    Ok(())
}
