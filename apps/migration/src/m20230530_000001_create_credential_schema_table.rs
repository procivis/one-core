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
                            .integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ClaimSchemas::Key).string())
                    .col(ColumnDef::new(ClaimSchemas::Datatype).enumeration(
                        Datatype::Table,
                        [Datatype::STRING, Datatype::DATE, Datatype::NUMBER],
                    ))
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
                            .integer()
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
                                [Format::JWT, Format::SD_JWT, Format::JSON_LD, Format::MDOC],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemas::RevocationMethod)
                            .enumeration(
                                RevocationMethod::Table,
                                [RevocationMethod::STATUSLIST2021, RevocationMethod::LVVC],
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

#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
#[derive(Iden)]
enum Format {
    Table,
    #[iden = "JWT"]
    JWT,
    #[iden = "SD_JWT"]
    SD_JWT,
    #[iden = "JSON_LD"]
    JSON_LD,
    #[iden = "MDOC"]
    MDOC,
}

#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
#[derive(Iden)]
enum RevocationMethod {
    Table,
    #[iden = "STATUSLIST2021"]
    STATUSLIST2021,
    #[iden = "LVVC"]
    LVVC,
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

#[allow(clippy::upper_case_acronyms, non_camel_case_types)]
#[derive(Iden)]
enum Datatype {
    Table,
    #[iden = "STRING"]
    STRING,
    #[iden = "DATE"]
    DATE,
    #[iden = "NUMBER"]
    NUMBER,
}
