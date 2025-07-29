use sea_orm_migration::prelude::*;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let create_relation_column = Table::alter()
            .table(Credential::Table)
            .add_column_if_not_exists(
                ColumnDef::new(Credential::CredentialBlobId)
                    .char_len(36)
                    .null(),
            )
            .to_owned();
        manager.exec_stmt(create_relation_column).await?;

        let find_credentials_with_credential_set = Query::select()
            .from(Credential::Table)
            .column(Credential::Id)
            .cond_where(
                Cond::all()
                    .add(Expr::col(Credential::CredentialBlobId).is_null())
                    .add(Expr::col(Credential::Credential).is_not_null())
                    .add(
                        Func::cust(LengthFunc)
                            .arg(Expr::col(Credential::Credential))
                            .gt(0),
                    ),
            )
            .to_owned();

        let found_credentials = manager
            .get_connection()
            .query_all(
                manager
                    .get_database_backend()
                    .build(&find_credentials_with_credential_set),
            )
            .await?;
        for found_credential in found_credentials.iter() {
            let id: String = found_credential.try_get_by_index(0)?;
            let set_blob_uuid = Query::update()
                .table(Credential::Table)
                .value(Credential::CredentialBlobId, Uuid::new_v4().to_string())
                .cond_where(Expr::col(Credential::Id).eq(id))
                .to_owned();
            manager.exec_stmt(set_blob_uuid).await?;
        }

        let copy_blob_data = Query::insert()
            .into_table(BlobStorage::Table)
            .columns([
                BlobStorage::Id,
                BlobStorage::CreatedDate,
                BlobStorage::LastModified,
                BlobStorage::Value,
                BlobStorage::Type,
            ])
            .select_from(
                Query::select()
                    .column(Credential::CredentialBlobId)
                    .column(Credential::CreatedDate)
                    .column(Credential::LastModified)
                    .column(Credential::Credential)
                    .expr(Expr::val("CREDENTIAL"))
                    .from(Credential::Table)
                    .cond_where(
                        Cond::all().add(Expr::col(Credential::CredentialBlobId).is_not_null()),
                    )
                    .to_owned(),
            )
            .unwrap()
            .to_owned();
        manager.exec_stmt(copy_blob_data).await?;

        let drop_credential_column = Table::alter()
            .table(Credential::Table)
            .drop_column(Credential::Credential)
            .to_owned();
        manager.exec_stmt(drop_credential_column).await?;
        Ok(())
    }
}

struct LengthFunc;

impl Iden for LengthFunc {
    fn unquoted(&self, s: &mut dyn Write) {
        write!(s, "LENGTH").unwrap();
    }
}

#[derive(DeriveIden, Clone)]
#[allow(clippy::enum_variant_names)]
enum Credential {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Credential,
    CredentialBlobId,
}

#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
    CreatedDate,
    LastModified,
    Value,
    Type,
}
