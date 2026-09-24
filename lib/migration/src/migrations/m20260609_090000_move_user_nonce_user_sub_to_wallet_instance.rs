use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{boolean, string, string_null};

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
                    .table(HolderWalletInstanceInitial::Table)
                    .drop_column(WalletInstanceColumn::UserNonce)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(HolderWalletInstanceInitial::Table)
                    .drop_column(WalletInstanceColumn::UserSub)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserNonce))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserSub))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn up_sqlite(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // Recreate holder_wallet_instance without user_nonce and user_sub
        manager
            .create_table(
                Table::create()
                    .table(HolderWalletInstanceNew::Table)
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
                    .col(boolean(HolderWalletInstanceNew::TrustedRpRequired))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-HolderWalletUnit-Organisation")
                            .from_tbl(HolderWalletInstanceNew::Table)
                            .from_col(HolderWalletInstanceInitial::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-HolderWalletUnitAuthKey-Key")
                            .from_tbl(HolderWalletInstanceNew::Table)
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
                    .into_table(HolderWalletInstanceNew::Table)
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
                        HolderWalletInstanceNew::TrustedRpRequired.into_iden(),
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
                            .column(HolderWalletInstanceNew::TrustedRpRequired)
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
                        HolderWalletInstanceNew::Table,
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

        // Add user_nonce and user_sub to wallet_instance
        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserNonce))
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WalletInstanceInitial::Table)
                    .add_column(string_null(WalletInstanceColumn::UserSub))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum HolderWalletInstanceNew {
    #[sea_orm(iden = "holder_wallet_instance_new")]
    Table,
    TrustedRpRequired,
}

#[derive(DeriveIden)]
enum WalletInstanceColumn {
    UserNonce,
    UserSub,
}
