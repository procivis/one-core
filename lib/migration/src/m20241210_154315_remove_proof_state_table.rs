use sea_orm::{ColumnTrait, DbBackend, EntityTrait, QueryFilter, Set, Unchanged};
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;
use crate::m20240110_000001_initial::ProofRequestStateEnum;
use crate::models_20241210::proof_state::ProofRequestState;
use crate::models_20241210::{proof, proof_state};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(
                        ColumnDef::new(Proof::State)
                            .enumeration(
                                ProofRequestStateEnum,
                                [
                                    ProofRequestState::Created,
                                    ProofRequestState::Pending,
                                    ProofRequestState::Accepted,
                                    ProofRequestState::Rejected,
                                    ProofRequestState::Error,
                                    ProofRequestState::Requested,
                                ],
                            )
                            .default("CREATED"),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(
                        ColumnDef::new(Proof::RequestedDate)
                            .datetime_millisecond_precision(manager),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .add_column(
                        ColumnDef::new(Proof::CompletedDate)
                            .datetime_millisecond_precision(manager),
                    )
                    .to_owned(),
            )
            .await?;

        match manager.get_database_backend() {
            DbBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"UPDATE `proof`
                       SET `state`=`proof_state`.`state`
                       FROM (
                         SELECT * FROM (
                           SELECT
                             `proof_state`.`proof_id`,
                             `proof_state`.`state`,
                             `proof_state`.`last_modified`
                           FROM `proof_state`
                           ORDER BY `proof_state`.`last_modified`
                           DESC)
                         GROUP BY `proof_id`)
                       AS `proof_state`
                       WHERE `proof`.`id` = `proof_state`.`proof_id`"#,
                    )
                    .await?;
            }
            _ => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"UPDATE proof AS p
                            JOIN (
                                SELECT ps.proof_id, ps.state
                                FROM proof_state AS ps
                                WHERE
                                    ps.created_date = (
                                        SELECT MAX(inner_ps.created_date)
                                        FROM proof_state AS inner_ps
                                        WHERE
                                            inner_ps.proof_id = ps.proof_id
                                    )
                            ) AS latest_state ON p.id = latest_state.proof_id
                            SET
                                p.state = latest_state.state;"#,
                    )
                    .await?;
            }
        }

        let db = manager.get_connection();

        let requested_dates = proof_state::Entity::find()
            .filter(
                proof_state::Column::State
                    .eq("REQUESTED")
                    .or(proof_state::Column::State.eq("PENDING")),
            )
            .all(db)
            .await?;
        for date in requested_dates {
            proof::Entity::update(proof::ActiveModel {
                id: Unchanged(date.proof_id),
                requested_date: Set(Some(date.created_date)),
                completed_date: Unchanged(Default::default()),
            })
            .exec(db)
            .await?;
        }

        let completed_dates = proof_state::Entity::find()
            .filter(
                proof_state::Column::State
                    .eq("ACCEPTED")
                    .or(proof_state::Column::State.eq("REJECTED")),
            )
            .all(db)
            .await?;
        for date in completed_dates {
            proof::Entity::update(proof::ActiveModel {
                id: Unchanged(date.proof_id),
                requested_date: Unchanged(Default::default()),
                completed_date: Set(Some(date.created_date)),
            })
            .exec(db)
            .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum Proof {
    Table,
    State,
    RequestedDate,
    CompletedDate,
}
