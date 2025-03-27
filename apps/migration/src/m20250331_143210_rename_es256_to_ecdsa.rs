use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("UPDATE `key` SET `key_type` = 'ECDSA' WHERE `key_type` = 'ES256'")
            .await?;

        Ok(())
    }
}
