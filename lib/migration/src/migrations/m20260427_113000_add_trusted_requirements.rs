use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, boolean_null, string, string_null, text_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char};
use crate::migrations::m20260417_150300_initial::{
    Organisation, VerifierInstance as VerifierInstanceInitial,
    WalletInstance as WalletInstanceInitial,
};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            self.up_sqlite(manager).await
        } else {
            self.up_sane(manager).await
        }
    }
}

impl Migration {
    async fn up_sane(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(boolean_null(WalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(WalletInstanceInitial::Table)
                    .values([(WalletInstance::TrustedRpRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .modify_column(boolean(WalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(VerifierInstanceInitial::Table)
                    .add_column(boolean_null(VerifierInstance::TrustedIssuerRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(VerifierInstanceInitial::Table)
                    .values([(VerifierInstance::TrustedIssuerRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(VerifierInstanceInitial::Table)
                    .modify_column(boolean(VerifierInstance::TrustedIssuerRequired))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // WalletInstance
        manager
            .create_table(
                Table::create()
                    .table(WalletInstance::TableNew)
                    .col(uuid_char(WalletInstanceInitial::Id).primary_key())
                    .col(timestamp(WalletInstanceInitial::CreatedDate, manager))
                    .col(timestamp(WalletInstanceInitial::LastModified, manager))
                    .col(timestamp_null(WalletInstanceInitial::LastIssuance, manager))
                    .col(string(WalletInstanceInitial::Name))
                    .col(string(WalletInstanceInitial::Os))
                    .col(string(WalletInstanceInitial::Status))
                    .col(string_null(WalletInstanceInitial::Nonce))
                    .col(string(WalletInstanceInitial::WalletProviderType))
                    .col(string(WalletInstanceInitial::WalletProviderName))
                    .col(text_null(WalletInstanceInitial::AuthenticationKeyJwk))
                    .col(uuid_char(WalletInstanceInitial::OrganisationId))
                    .col(boolean(WalletInstance::TrustedRpRequired))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-WalletUnit-OrganisationId")
                            .from_tbl(WalletInstance::TableNew)
                            .from_col(WalletInstanceInitial::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::insert()
                    .into_table(WalletInstance::TableNew)
                    .columns([
                        WalletInstanceInitial::Id.into_iden(),
                        WalletInstanceInitial::CreatedDate.into_iden(),
                        WalletInstanceInitial::LastModified.into_iden(),
                        WalletInstanceInitial::LastIssuance.into_iden(),
                        WalletInstanceInitial::Name.into_iden(),
                        WalletInstanceInitial::Os.into_iden(),
                        WalletInstanceInitial::Status.into_iden(),
                        WalletInstanceInitial::Nonce.into_iden(),
                        WalletInstanceInitial::WalletProviderType.into_iden(),
                        WalletInstanceInitial::WalletProviderName.into_iden(),
                        WalletInstanceInitial::AuthenticationKeyJwk.into_iden(),
                        WalletInstanceInitial::OrganisationId.into_iden(),
                        WalletInstance::TrustedRpRequired.into_iden(),
                    ])
                    .select_from(
                        Query::select()
                            .columns([
                                WalletInstanceInitial::Id,
                                WalletInstanceInitial::CreatedDate,
                                WalletInstanceInitial::LastModified,
                                WalletInstanceInitial::LastIssuance,
                                WalletInstanceInitial::Name,
                                WalletInstanceInitial::Os,
                                WalletInstanceInitial::Status,
                                WalletInstanceInitial::Nonce,
                                WalletInstanceInitial::WalletProviderType,
                                WalletInstanceInitial::WalletProviderName,
                                WalletInstanceInitial::AuthenticationKeyJwk,
                                WalletInstanceInitial::OrganisationId,
                            ])
                            .expr_as(
                                Expr::value(false),
                                WalletInstance::TrustedRpRequired.into_iden(),
                            )
                            .from(WalletInstanceInitial::Table)
                            .to_owned(),
                    )
                    .map_err(|e| DbErr::Migration(e.to_string()))?
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(WalletInstanceInitial::Table).to_owned())
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(WalletInstance::TableNew, WalletInstanceInitial::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-WalletUnit-Organisation-AuthenticationKey-Unique")
                    .unique()
                    .table(WalletInstanceInitial::Table)
                    .col(WalletInstanceInitial::AuthenticationKeyJwk)
                    .col(WalletInstanceInitial::OrganisationId)
                    .to_owned(),
            )
            .await?;

        // VerifierInstance
        manager
            .create_table(
                Table::create()
                    .table(VerifierInstance::TableNew)
                    .col(uuid_char(VerifierInstanceInitial::Id).primary_key())
                    .col(timestamp(VerifierInstanceInitial::CreatedDate, manager))
                    .col(timestamp(VerifierInstanceInitial::LastModified, manager))
                    .col(string(VerifierInstanceInitial::ProviderUrl))
                    .col(string(VerifierInstanceInitial::ProviderName))
                    .col(string(VerifierInstanceInitial::ProviderType))
                    .col(uuid_char(VerifierInstanceInitial::OrganisationId))
                    .col(boolean(VerifierInstance::TrustedIssuerRequired))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-VerifierInstance-Organisation")
                            .from_tbl(VerifierInstance::TableNew)
                            .from_col(VerifierInstanceInitial::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::insert()
                    .into_table(VerifierInstance::TableNew)
                    .columns([
                        VerifierInstanceInitial::Id.into_iden(),
                        VerifierInstanceInitial::CreatedDate.into_iden(),
                        VerifierInstanceInitial::LastModified.into_iden(),
                        VerifierInstanceInitial::ProviderUrl.into_iden(),
                        VerifierInstanceInitial::ProviderName.into_iden(),
                        VerifierInstanceInitial::ProviderType.into_iden(),
                        VerifierInstanceInitial::OrganisationId.into_iden(),
                        VerifierInstance::TrustedIssuerRequired.into_iden(),
                    ])
                    .select_from(
                        Query::select()
                            .columns([
                                VerifierInstanceInitial::Id,
                                VerifierInstanceInitial::CreatedDate,
                                VerifierInstanceInitial::LastModified,
                                VerifierInstanceInitial::ProviderUrl,
                                VerifierInstanceInitial::ProviderName,
                                VerifierInstanceInitial::ProviderType,
                                VerifierInstanceInitial::OrganisationId,
                            ])
                            .expr_as(
                                Expr::value(false),
                                VerifierInstance::TrustedIssuerRequired.into_iden(),
                            )
                            .from(VerifierInstanceInitial::Table)
                            .to_owned(),
                    )
                    .map_err(|e| DbErr::Migration(e.to_string()))?
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(VerifierInstanceInitial::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(VerifierInstance::TableNew, VerifierInstanceInitial::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-VerifierInstance-OrganisationId-Unique")
                    .unique()
                    .table(VerifierInstanceInitial::Table)
                    .col(VerifierInstanceInitial::OrganisationId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum WalletInstance {
    TrustedRpRequired,
    TableNew,
}

#[derive(DeriveIden)]
pub enum VerifierInstance {
    TrustedIssuerRequired,
    TableNew,
}
