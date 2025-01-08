use sea_orm::FromQueryResult;
use sea_orm_migration::prelude::*;

use crate::m20240110_000001_initial::Did;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, FromQueryResult)]
pub struct DidQueryResult {
    id: String,
    did: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        let dids = DidQueryResult::find_by_statement(
            backend.build(
                Query::select()
                    .columns([Did::Id, Did::Did])
                    .from(Did::Table)
                    .cond_where(Expr::col(Did::Method).eq("SD_JWT_VC_ISSUER_METADATA")),
            ),
        )
        .all(db)
        .await?;

        for did in dids.iter().filter(|did| !did.did.starts_with("did:")) {
            let did_value = format!(
                "did:sd_jwt_vc_issuer_metadata:{}",
                urlencoding::encode(&did.did)
            );

            db.execute(
                backend.build(
                    Query::update()
                        .table(Did::Table)
                        .value(Did::Did, did_value)
                        .and_where(Expr::col(Did::Id).eq(&did.id)),
                ),
            )
            .await?;
        }

        Ok(())
    }
}
