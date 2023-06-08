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
                            .char_len(36)
                            .not_null()
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
                    .col(
                        ColumnDef::new(ClaimSchemas::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchemas::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchemas::CredentialId)
                            .char_len(36)
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
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemas::DeletedAt)
                            .date_time()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemas::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemas::LastModified)
                            .date_time()
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
                    .col(
                        ColumnDef::new(CredentialSchemas::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchemaClaims::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchemaClaims::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaims::ProofSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-ClaimSchema_ProofSchema")
                            .col(ProofSchemaClaims::ClaimSchemaId)
                            .col(ProofSchemaClaims::ProofSchemaId)
                            .primary(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchemas::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchemas::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ProofSchemas::DeletedAt).date_time().null())
                    .col(
                        ColumnDef::new(ProofSchemas::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemas::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProofSchemas::Name).string().not_null())
                    .col(
                        ColumnDef::new(ProofSchemas::ExpireDuration)
                            .unsigned()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemas::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ClaimSchemas::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(CredentialSchemas::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ProofSchemaClaims::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ProofSchemas::Table).to_owned())
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
    OrganisationId,
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

#[derive(Iden)]
enum ProofSchemas {
    Table,
    Id,
    DeletedAt,
    CreatedDate,
    LastModified,
    Name,
    ExpireDuration,
    OrganisationId,
}

#[derive(Iden)]
enum ProofSchemaClaims {
    Table,
    ClaimSchemaId, // ClaimSchemas::Id
    ProofSchemaId, // ProofSchemas::Id
}
