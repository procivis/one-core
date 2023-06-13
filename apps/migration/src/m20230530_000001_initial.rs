use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CredentialSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CredentialSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::DeletedAt)
                            .date_time()
                            .null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CredentialSchema::Name).string().not_null())
                    .col(
                        ColumnDef::new(CredentialSchema::Format)
                            .enumeration(
                                Format::Table,
                                [Format::Jwt, Format::SdJwt, Format::JsonLd, Format::Mdoc],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::RevocationMethod)
                            .enumeration(
                                RevocationMethod::Table,
                                [RevocationMethod::StatusList2021, RevocationMethod::Lvvc],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchema::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ClaimSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ClaimSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ClaimSchema::Key).string().not_null())
                    .col(
                        ColumnDef::new(ClaimSchema::Datatype)
                            .enumeration(
                                Datatype::Table,
                                [Datatype::String, Datatype::Date, Datatype::Number],
                            )
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchema::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchema::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ClaimSchema::CredentialId)
                            .char_len(36)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ClaimSchema-CredentialId")
                            .from(ClaimSchema::Table, ClaimSchema::CredentialId)
                            .to(CredentialSchema::Table, CredentialSchema::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchema::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ProofSchema::DeletedAt).date_time().null())
                    .col(
                        ColumnDef::new(ProofSchema::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ProofSchema::Name).string().not_null())
                    .col(
                        ColumnDef::new(ProofSchema::ExpireDuration)
                            .unsigned()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchema::OrganisationId)
                            .char_len(36)
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchemaClaim::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchemaClaim::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaim::ProofSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaim::IsRequired)
                            .boolean()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-ClaimSchema_ProofSchema")
                            .col(ProofSchemaClaim::ClaimSchemaId)
                            .col(ProofSchemaClaim::ProofSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ClaimSchema_ProofSchema-ClaimId")
                            .from_tbl(ProofSchemaClaim::Table)
                            .from_col(ProofSchemaClaim::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ClaimSchema_ProofSchema-ProofId")
                            .from_tbl(ProofSchemaClaim::Table)
                            .from_col(ProofSchemaClaim::ProofSchemaId)
                            .to_tbl(ProofSchema::Table)
                            .to_col(ProofSchema::Id),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ClaimSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ProofSchemaClaim::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ProofSchema::Table).to_owned())
            .await
    }
}

#[derive(Iden)]
enum CredentialSchema {
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
enum ClaimSchema {
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
enum ProofSchema {
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
enum ProofSchemaClaim {
    Table,
    ClaimSchemaId,
    ProofSchemaId,
    IsRequired,
}
