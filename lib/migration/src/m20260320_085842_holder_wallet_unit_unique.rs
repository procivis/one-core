use std::collections::HashMap;

use sea_orm::{DbBackend, FromQueryResult};
use sea_orm_migration::prelude::*;
use time::OffsetDateTime;

use crate::m20240110_000001_initial::Key;
use crate::m20251029_144801_add_holder_wallet_unit::{HolderWalletUnit, WalletUnitAttestation};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        if backend == DbBackend::Postgres {
            return Ok(());
        }

        let db = manager.get_connection();
        let units = Unit::find_by_statement(
            backend.build(
                Query::select()
                    .columns([
                        HolderWalletUnit::Id,
                        HolderWalletUnit::CreatedDate,
                        HolderWalletUnit::OrganisationId,
                    ])
                    .from(HolderWalletUnit::Table),
            ),
        )
        .all(db)
        .await?;

        let mut units_per_org: HashMap<String, Vec<Unit>> = HashMap::new();
        for unit in units {
            units_per_org
                .entry(unit.organisation_id.to_owned())
                .and_modify(|list| list.push(unit.to_owned()))
                .or_insert(vec![unit]);
        }

        let mut units_to_be_removed = vec![];
        for (_, mut units) in units_per_org {
            if units.len() > 1 {
                units.sort_by_key(|u| u.created_date);
                units.pop(); // remove/retain the newest
                units_to_be_removed.extend(units.into_iter().map(|u| u.id));
            }
        }

        tracing::info!(
            "Removing duplicit holder-wallet-units: ({})",
            units_to_be_removed.join(",")
        );

        for ref unit_id in units_to_be_removed {
            manager
                .exec_stmt(
                    Query::delete()
                        .from_table(WalletUnitAttestation::Table)
                        .and_where(Expr::col(WalletUnitAttestation::HolderWalletUnitId).eq(unit_id))
                        .to_owned(),
                )
                .await?;
            manager
                .exec_stmt(
                    Query::delete()
                        .from_table(HolderWalletUnit::Table)
                        .and_where(Expr::col(HolderWalletUnit::Id).eq(unit_id))
                        .to_owned(),
                )
                .await?;
        }

        if backend == DbBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(HolderWalletUnit::Table)
                        .drop_foreign_key(Alias::new("fk-HolderWalletUnitAuthKey-Key"))
                        .to_owned(),
                )
                .await?;
        }

        manager
            .drop_index(
                Index::drop()
                    .name("index-HolderWalletUnit-AuthenticationKey-Unique")
                    .table(HolderWalletUnit::Table)
                    .to_owned(),
            )
            .await?;

        if backend == DbBackend::MySql {
            manager
                .alter_table(
                    Table::alter()
                        .table(HolderWalletUnit::Table)
                        .add_foreign_key(
                            ForeignKey::create()
                                .name("fk-HolderWalletUnitAuthKey-Key")
                                .from_tbl(HolderWalletUnit::Table)
                                .from_col(HolderWalletUnit::AuthenticationKeyId)
                                .to_tbl(Key::Table)
                                .to_col(Key::Id)
                                .get_foreign_key(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_index(
                Index::create()
                    .unique()
                    .name("index-HolderWalletUnit-OrganisationId-Unique")
                    .table(HolderWalletUnit::Table)
                    .col(HolderWalletUnit::OrganisationId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(FromQueryResult, Clone)]
struct Unit {
    pub id: String,
    pub organisation_id: String,
    pub created_date: OffsetDateTime,
}
