use sea_orm_migration::prelude::*;
use std::fmt;

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
                        ColumnDef::new(Proof::Exchange)
                            .string()
                            .not_null()
                            .default("OPENID4VC"),
                    )
                    .to_owned(),
            )
            .await?;

        let query = format!(
            "UPDATE {} SET {} = {}",
            Proof::Table,
            Proof::Exchange,
            Proof::Transport
        );
        manager.get_connection().execute_unprepared(&query).await?;

        let query = format!("UPDATE {} SET {} = 'HTTP'", Proof::Table, Proof::Transport,);
        manager.get_connection().execute_unprepared(&query).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let query = format!(
            "UPDATE {} SET {} = {}",
            Proof::Table,
            Proof::Transport,
            Proof::Exchange,
        );
        manager.get_connection().execute_unprepared(&query).await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Proof::Table)
                    .drop_column(Proof::Exchange)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}

#[derive(Iden)]
enum Proof {
    Table,
    Transport,
    Exchange,
}

impl fmt::Display for Proof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Proof::Table => "proof",
                Proof::Transport => "transport",
                Proof::Exchange => "exchange",
            }
        )
    }
}
