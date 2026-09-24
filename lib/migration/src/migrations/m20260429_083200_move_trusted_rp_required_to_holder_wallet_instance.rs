use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, boolean_null, string};

use crate::datatype::{timestamp, uuid_char, uuid_char_null};
use crate::migrations::m20260417_150300_initial::{
    HolderWalletInstance as HolderWalletInstanceInitial, Key, Organisation,
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
                    .drop_column(Alias::new("trusted_rp_required"))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .add_column(boolean_null(HolderWalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(HolderWalletInstanceInitial::Table)
                    .values([(HolderWalletInstance::TrustedRpRequired, false.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .modify_column(boolean(HolderWalletInstance::TrustedRpRequired))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // WalletInstance
        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .drop_column(Alias::new("trusted_rp_required"))
                    .to_owned(),
            )
            .await?;

        // HolderWalletInstance
        manager
            .create_table(
                Table::create()
                    .table(HolderWalletInstance::TableNew)
                    .col(uuid_char(HolderWalletInstanceInitial::Id).primary_key())
                    .col(timestamp(HolderWalletInstanceInitial::CreatedDate, manager))
                    .col(timestamp(
                        HolderWalletInstanceInitial::LastModified,
                        manager,
                    ))
                    .col(string(HolderWalletInstanceInitial::WalletProviderUrl))
                    .col(string(HolderWalletInstanceInitial::WalletProviderName))
                    .col(string(HolderWalletInstanceInitial::WalletProviderType))
                    .col(string(HolderWalletInstanceInitial::Status))
                    .col(uuid_char(HolderWalletInstanceInitial::ProviderWalletUnitId))
                    .col(uuid_char(HolderWalletInstanceInitial::OrganisationId))
                    .col(uuid_char_null(
                        HolderWalletInstanceInitial::AuthenticationKeyId,
                    ))
                    .col(boolean(HolderWalletInstance::TrustedRpRequired))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-HolderWalletUnit-Organisation")
                            .from_tbl(HolderWalletInstance::TableNew)
                            .from_col(HolderWalletInstanceInitial::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-HolderWalletUnitAuthKey-Key")
                            .from_tbl(HolderWalletInstance::TableNew)
                            .from_col(HolderWalletInstanceInitial::AuthenticationKeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::insert()
                    .into_table(HolderWalletInstance::TableNew)
                    .columns([
                        HolderWalletInstanceInitial::Id.into_iden(),
                        HolderWalletInstanceInitial::CreatedDate.into_iden(),
                        HolderWalletInstanceInitial::LastModified.into_iden(),
                        HolderWalletInstanceInitial::WalletProviderUrl.into_iden(),
                        HolderWalletInstanceInitial::WalletProviderName.into_iden(),
                        HolderWalletInstanceInitial::WalletProviderType.into_iden(),
                        HolderWalletInstanceInitial::Status.into_iden(),
                        HolderWalletInstanceInitial::ProviderWalletUnitId.into_iden(),
                        HolderWalletInstanceInitial::OrganisationId.into_iden(),
                        HolderWalletInstanceInitial::AuthenticationKeyId.into_iden(),
                        HolderWalletInstance::TrustedRpRequired.into_iden(),
                    ])
                    .select_from(
                        Query::select()
                            .columns([
                                HolderWalletInstanceInitial::Id,
                                HolderWalletInstanceInitial::CreatedDate,
                                HolderWalletInstanceInitial::LastModified,
                                HolderWalletInstanceInitial::WalletProviderUrl,
                                HolderWalletInstanceInitial::WalletProviderName,
                                HolderWalletInstanceInitial::WalletProviderType,
                                HolderWalletInstanceInitial::Status,
                                HolderWalletInstanceInitial::ProviderWalletUnitId,
                                HolderWalletInstanceInitial::OrganisationId,
                                HolderWalletInstanceInitial::AuthenticationKeyId,
                            ])
                            .expr_as(
                                Expr::value(false),
                                HolderWalletInstance::TrustedRpRequired.into_iden(),
                            )
                            .from(HolderWalletInstanceInitial::Table)
                            .to_owned(),
                    )
                    .map_err(|e| DbErr::Migration(e.to_string()))?
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(
                Table::drop()
                    .table(HolderWalletInstanceInitial::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .rename_table(
                Table::rename()
                    .table(
                        HolderWalletInstance::TableNew,
                        HolderWalletInstanceInitial::Table,
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("index-HolderWalletUnit-OrganisationId-Unique")
                    .unique()
                    .table(HolderWalletInstanceInitial::Table)
                    .col(HolderWalletInstanceInitial::OrganisationId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum HolderWalletInstance {
    TrustedRpRequired,
    TableNew,
}
