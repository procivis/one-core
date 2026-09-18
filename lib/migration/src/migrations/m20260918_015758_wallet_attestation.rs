use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::string;
use time::OffsetDateTime;

use crate::datatype::{large_blob, timestamp, timestamp_seconds_null, uuid_char, uuid_char_null};
use crate::migrations::m20260417_150300_initial::{Key, WalletInstanceAttestation};
use crate::migrations::m20260720_091548_instance::{Instance, NewWalletInstanceAttestation};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(WalletAttestation::Table)
                    .col(uuid_char(WalletAttestation::Id).primary_key())
                    .col(timestamp(WalletAttestation::CreatedDate, manager))
                    .col(timestamp(WalletAttestation::LastModified, manager))
                    .col(timestamp_seconds_null(
                        WalletAttestation::ExpirationDate,
                        manager,
                    ))
                    .col(large_blob(WalletAttestation::Attestation, manager))
                    .col(uuid_char(WalletAttestation::InstanceId))
                    .col(string(WalletAttestation::Type))
                    .col(uuid_char_null(WalletAttestation::AttestedKeyId))
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-WalletAttestation-InstanceId")
                            .from_tbl(WalletAttestation::Table)
                            .from_col(WalletAttestation::InstanceId)
                            .to_tbl(Instance::Table)
                            .to_col(Instance::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-WalletAttestation-AttestedKeyId")
                            .from_tbl(WalletAttestation::Table)
                            .from_col(WalletAttestation::AttestedKeyId)
                            .to_tbl(Key::Table)
                            .to_col(Key::Id),
                    )
                    .to_owned(),
            )
            .await?;

        #[derive(FromQueryResult)]
        struct OldEntry {
            id: String,
            created_date: OffsetDateTime,
            last_modified: OffsetDateTime,
            expiration_date: OffsetDateTime,
            #[sea_orm(column_type = "Blob")]
            attestation: Vec<u8>,
            attested_key_id: String,
            instance_id: String,
        }

        let db = manager.get_connection();
        let backend = db.get_database_backend();
        let old_entries = OldEntry::find_by_statement(
            backend.build(
                Query::select()
                    .columns([
                        NewWalletInstanceAttestation::Id,
                        NewWalletInstanceAttestation::CreatedDate,
                        NewWalletInstanceAttestation::LastModified,
                        NewWalletInstanceAttestation::ExpirationDate,
                        NewWalletInstanceAttestation::Attestation,
                        NewWalletInstanceAttestation::AttestedKeyId,
                        NewWalletInstanceAttestation::InstanceId,
                    ])
                    .from(WalletInstanceAttestation::Table),
            ),
        )
        .all(db)
        .await?;

        for entry in old_entries {
            db.execute(
                backend.build(
                    Query::insert()
                        .into_table(WalletAttestation::Table)
                        .columns([
                            WalletAttestation::Id,
                            WalletAttestation::CreatedDate,
                            WalletAttestation::LastModified,
                            WalletAttestation::ExpirationDate,
                            WalletAttestation::Attestation,
                            WalletAttestation::AttestedKeyId,
                            WalletAttestation::InstanceId,
                            WalletAttestation::Type,
                        ])
                        .values([
                            entry.id.into(),
                            entry.created_date.into(),
                            entry.last_modified.into(),
                            entry.expiration_date.into(),
                            entry.attestation.into(),
                            entry.attested_key_id.into(),
                            entry.instance_id.into(),
                            "KA".into(),
                        ])
                        .map_err(|e| DbErr::Migration(e.to_string()))?,
                ),
            )
            .await?;
        }

        manager
            .drop_table(
                Table::drop()
                    .table(WalletInstanceAttestation::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum WalletAttestation {
    Table,
    Id,
    CreatedDate,
    LastModified,
    ExpirationDate,
    Attestation,
    InstanceId,
    AttestedKeyId,
    Type,
}
