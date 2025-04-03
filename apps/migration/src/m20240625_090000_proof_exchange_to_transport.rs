use std::fmt;

use sea_orm_migration::prelude::*;

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
}

#[derive(Iden)]
pub enum Proof {
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
                Self::Table => "proof",
                Self::Transport => "transport",
                Self::Exchange => "exchange",
            }
        )
    }
}
