use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                r#"
                UPDATE credential
                SET type = 'BATCH_PARENT'
                WHERE type = 'SINGLE'
                  AND EXISTS (
                      SELECT 1
                      FROM credential AS child
                      WHERE child.parent_id = credential.id
                  )
                  AND EXISTS (
                      SELECT 1
                      FROM credential_schema_format AS csf
                      WHERE csf.credential_schema_id = credential.credential_schema_id
                        AND csf.format = 'MDOC'
                  );
                "#,
            )
            .await?;

        Ok(())
    }
}
