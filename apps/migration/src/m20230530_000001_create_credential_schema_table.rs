use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ClaimSchemas::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ClaimSchemas::Id)
                            .unsigned()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ClaimSchemas::Key).string().not_null())
                    .col(
                        ColumnDef::new(ClaimSchemas::Datatype)
                            .enumeration(
                                Datatype::Table,
                                [Datatype::String, Datatype::Date, Datatype::Number],
                            )
                            .not_null(),
                    )
                    .col(ColumnDef::new(ClaimSchemas::CreatedDate).time().not_null())
                    .col(ColumnDef::new(ClaimSchemas::LastModified).time().not_null())
                    .col(
                        ColumnDef::new(ClaimSchemas::CredentialId)
                            .integer()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialSchemas::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CredentialSchemas::Id)
                            .unsigned()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(CredentialSchemas::DeletedAt).time())
                    .col(
                        ColumnDef::new(CredentialSchemas::CreatedDate)
                            .time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemas::LastModified)
                            .time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CredentialSchemas::Name).string().not_null())
                    .col(
                        ColumnDef::new(CredentialSchemas::Format)
                            .enumeration(
                                Format::Table,
                                [Format::Jwt, Format::SdJwt, Format::JsonLd, Format::Mdoc],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemas::RevocationMethod)
                            .enumeration(
                                RevocationMethod::Table,
                                [RevocationMethod::StatusList2021, RevocationMethod::Lvvc],
                            )
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(CredentialSchemas::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum CredentialSchemas {
    Table,
    Id,
    DeletedAt,
    CreatedDate,
    LastModified,
    Name,
    Format,
    RevocationMethod,
}

#[derive(Iden)]
enum Format {
    Table,
    #[iden = "JWT"]
    Jwt,
    #[iden = "SD_JWT"]
    SdJwt,
    #[iden = "JSON_LD"]
    JsonLd,
    #[iden = "MDOC"]
    Mdoc,
}

#[derive(Iden)]
enum RevocationMethod {
    Table,
    #[iden = "STATUSLIST2021"]
    StatusList2021,
    #[iden = "LVVC"]
    Lvvc,
}

#[derive(Iden)]
enum ClaimSchemas {
    Table,
    Id,
    Datatype,
    Key,
    CreatedDate,
    LastModified,
    CredentialId,
}

#[derive(Iden)]
enum Datatype {
    Table,
    #[iden = "STRING"]
    String,
    #[iden = "DATE"]
    Date,
    #[iden = "NUMBER"]
    Number,
}
