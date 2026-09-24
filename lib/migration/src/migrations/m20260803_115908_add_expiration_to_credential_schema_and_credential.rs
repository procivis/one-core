use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::integer_null;

use crate::datatype::timestamp_null;
use crate::migrations::m20260417_150300_initial::{Credential, CredentialSchema};
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

const TWO_YEARS_IN_SECONDS: i32 = 63_072_000;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CredentialSchema::Table)
                    .add_column(integer_null(Col::Expiration))
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(CredentialSchema::Table)
                    .values([(Col::Expiration, TWO_YEARS_IN_SECONDS.into())])
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(timestamp_null(Col::ExpiresAt, manager))
                    .to_owned(),
            )
            .await?;

        let update_expires_at = match manager.supported_db_type() {
            SupportedDbType::MySql => format!(
                "UPDATE credential SET expires_at = DATE_ADD(issuance_date, INTERVAL {TWO_YEARS_IN_SECONDS} SECOND) WHERE issuance_date IS NOT NULL"
            ),
            SupportedDbType::Postgres => format!(
                "UPDATE credential SET expires_at = issuance_date + INTERVAL '{TWO_YEARS_IN_SECONDS} seconds' WHERE issuance_date IS NOT NULL"
            ),
            SupportedDbType::Sqlite => format!(
                "UPDATE credential SET expires_at = datetime(issuance_date, '+{TWO_YEARS_IN_SECONDS} seconds') WHERE issuance_date IS NOT NULL"
            ),
        };

        manager
            .get_connection()
            .execute_unprepared(&update_expires_at)
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum Col {
    Expiration,
    ExpiresAt,
}
