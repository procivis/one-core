use sea_orm::DatabaseBackend;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        const AFFECTED_FORMATS: [&str; 2] = ["JWT", "SD_JWT"];
        const AFFECTED_CLAIM_SCHEMA_KEY: &str = "id";
        const AFFECTED_CLAIM_SCHEMA_KEY_NEW: &str = "_id";

        let (soft_delete_credential, update_claim_schema_key, update_claim_path) = match manager
            .get_database_backend()
        {
            DatabaseBackend::Sqlite => {
                let soft_delete_credential = format!(
                    "
                        UPDATE credential 
                        SET deleted_at = CURRENT_TIMESTAMP
                        WHERE credential_schema_id IN (
                            SELECT credential_schema.id 
                            FROM credential_schema
                            JOIN credential_schema_claim_schema ON credential_schema.id = credential_schema_claim_schema.credential_schema_id
                            JOIN claim_schema ON credential_schema_claim_schema.claim_schema_id = claim_schema.id
                            WHERE claim_schema.key = '{AFFECTED_CLAIM_SCHEMA_KEY}' AND credential_schema.format IN ('{}', '{}')
                        )
                    ",
                    AFFECTED_FORMATS[0],
                    AFFECTED_FORMATS[1],
                );

                let update_claim_path = format!(
                    "
                        UPDATE claim 
                        SET path = '{AFFECTED_CLAIM_SCHEMA_KEY_NEW}'
                        WHERE path = '{AFFECTED_CLAIM_SCHEMA_KEY}' 
                        AND claim_schema_id IN (
                            SELECT claim_schema.id 
                            FROM claim_schema
                            JOIN credential_schema_claim_schema ON claim_schema.id = credential_schema_claim_schema.claim_schema_id
                            JOIN credential_schema ON credential_schema_claim_schema.credential_schema_id = credential_schema.id
                            WHERE claim_schema.key = '{AFFECTED_CLAIM_SCHEMA_KEY}' AND credential_schema.format IN ('{}', '{}')
                        )
                    ",
                    AFFECTED_FORMATS[0],
                    AFFECTED_FORMATS[1],
                );

                let update_claim_schema_key = format!(
                    "
                        UPDATE claim_schema 
                        SET key = '{AFFECTED_CLAIM_SCHEMA_KEY_NEW}'
                        WHERE key = '{AFFECTED_CLAIM_SCHEMA_KEY}' 
                        AND id IN (
                            SELECT claim_schema_id 
                            FROM credential_schema_claim_schema 
                            WHERE credential_schema_id IN (
                                SELECT id 
                                FROM credential_schema 
                                WHERE format IN ('{}', '{}')
                            )
                        )
                    ",
                    AFFECTED_FORMATS[0], AFFECTED_FORMATS[1],
                );

                (
                    soft_delete_credential,
                    update_claim_schema_key,
                    update_claim_path,
                )
            }
            _ => {
                let soft_delete_credential = format!("
                        UPDATE credential
                        JOIN credential_schema ON credential.credential_schema_id = credential_schema.id
                        JOIN credential_schema_claim_schema ON credential_schema.id = credential_schema_claim_schema.credential_schema_id
                        JOIN claim_schema ON credential_schema_claim_schema.claim_schema_id = claim_schema.id
                        SET credential.deleted_at = CURRENT_TIMESTAMP
                        WHERE claim_schema.key = '{AFFECTED_CLAIM_SCHEMA_KEY}' AND credential_schema.format IN ('{}', '{}')
                    ",
                    AFFECTED_FORMATS[0], AFFECTED_FORMATS[1],
                );

                let update_claim_path = format!("
                        UPDATE claim
                        JOIN claim_schema ON claim.claim_schema_id = claim_schema.id
                        JOIN credential_schema_claim_schema ON claim_schema.id = credential_schema_claim_schema.claim_schema_id
                        JOIN credential_schema ON credential_schema_claim_schema.credential_schema_id = credential_schema.id
                        SET claim.path = '{AFFECTED_CLAIM_SCHEMA_KEY_NEW}'
                        WHERE claim.path = '{AFFECTED_CLAIM_SCHEMA_KEY}' AND credential_schema.format IN ('{}', '{}')
                    ",
                    AFFECTED_FORMATS[0], AFFECTED_FORMATS[1],
                );

                let update_claim_schema_key = format!("
                        UPDATE claim_schema
                        JOIN credential_schema_claim_schema ON claim_schema.id = credential_schema_claim_schema.claim_schema_id
                        JOIN credential_schema ON credential_schema_claim_schema.credential_schema_id = credential_schema.id
                        SET claim_schema.key = '{AFFECTED_CLAIM_SCHEMA_KEY_NEW}'
                        WHERE claim_schema.key = '{AFFECTED_CLAIM_SCHEMA_KEY}' AND credential_schema.format IN ('{}', '{}')
                    ",
                    AFFECTED_FORMATS[0], AFFECTED_FORMATS[1],
                );

                (
                    soft_delete_credential,
                    update_claim_schema_key,
                    update_claim_path,
                )
            }
        };

        db.execute_unprepared(&soft_delete_credential).await?;
        db.execute_unprepared(&update_claim_path).await?;
        db.execute_unprepared(&update_claim_schema_key).await?;

        Ok(())
    }
}
