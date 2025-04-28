use sea_orm::EnumIter;
use sea_orm_migration::prelude::*;

use crate::datatype::ColumnDefExt;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Credential::State)
                            .enumeration(
                                CredentialStateEnum,
                                [
                                    UpdatedStates::Created,
                                    UpdatedStates::Pending,
                                    UpdatedStates::Offered,
                                    UpdatedStates::Accepted,
                                    UpdatedStates::Rejected,
                                    UpdatedStates::Revoked,
                                    UpdatedStates::Suspended,
                                    UpdatedStates::Error,
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
                    .table(Credential::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(Credential::SuspendEndDate)
                            .datetime_millisecond_precision(manager)
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        let db_backend = manager.get_database_backend();

        match db_backend {
            sea_orm::DatabaseBackend::MySql => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"UPDATE credential AS c
                            JOIN (
                                SELECT cs.credential_id, cs.state
                                FROM credential_state AS cs
                                WHERE
                                    cs.created_date = (
                                        SELECT MAX(inner_cs.created_date)
                                        FROM credential_state AS inner_cs
                                        WHERE
                                            inner_cs.credential_id = cs.credential_id
                                    )
                            ) AS latest_state ON c.id = latest_state.credential_id
                            SET
                                c.state = latest_state.state;"#,
                    )
                    .await?;

                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"UPDATE credential AS c
                            JOIN (
                                SELECT cs.credential_id, cs.state, cs.suspend_end_date
                                FROM credential_state AS cs
                                WHERE
                                    cs.created_date = (
                                        SELECT MAX(inner_cs.created_date)
                                        FROM credential_state AS inner_cs
                                        WHERE
                                            inner_cs.credential_id = cs.credential_id
                                            AND inner_cs.state = 'SUSPENDED'
                                    )
                            ) AS latest_state ON c.id = latest_state.credential_id
                            SET
                                c.suspend_end_date = latest_state.suspend_end_date;"#,
                    )
                    .await?;
            }
            sea_orm::DatabaseBackend::Postgres => {}
            sea_orm::DatabaseBackend::Sqlite => {
                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"UPDATE `credential` as `c`
                        SET `state`=`credential_state`.`state`
                        FROM (
                        SELECT * FROM (
                        SELECT
                        `cs`.`credential_id`,
                        `cs`.`state`,
                        `cs`.`created_date`
                        FROM `credential_state` as `cs`
                        ORDER BY `cs`.`created_date`
                        DESC)
                        GROUP BY `credential_id`)
                        AS `credential_state`
                        WHERE `c`.`id` = `credential_state`.`credential_id`"#,
                    )
                    .await?;

                manager
                    .get_connection()
                    .execute_unprepared(
                        r#"UPDATE `credential` AS `c`
                        SET `suspend_end_date`=`credential_state`.`suspend_end_date`
                        FROM (
                        SELECT * FROM (
                        SELECT
                        `cs`.`credential_id`,
                        `cs`.`state`,
                        `cs`.`created_date`,
                        `cs`.`suspend_end_date`
                        FROM `credential_state` AS `cs`
                        WHERE `cs`.`state` = 'SUSPENDED'
                        ORDER BY `cs`.`created_date`
                        DESC)
                        GROUP BY `credential_id`)
                        AS `credential_state`
                        WHERE `c`.`id` = `credential_state`.`credential_id`"#,
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    State,
    SuspendEndDate,
}

#[derive(Iden)]
pub struct CredentialStateEnum;

#[derive(Iden, EnumIter)]
pub enum UpdatedStates {
    #[iden = "CREATED"]
    Created,
    #[iden = "PENDING"]
    Pending,
    #[iden = "OFFERED"]
    Offered,
    #[iden = "ACCEPTED"]
    Accepted,
    #[iden = "REJECTED"]
    Rejected,
    #[iden = "REVOKED"]
    Revoked,
    #[iden = "SUSPENDED"]
    Suspended,
    #[iden = "ERROR"]
    Error,
}
