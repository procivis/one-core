use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Organisation::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(Organisation::Id)
                            .char_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Organisation::CreatedDate)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Organisation::LastModified)
                            .date_time()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

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
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-CredentialSchema-OrganisationId")
                            .from_tbl(CredentialSchema::Table)
                            .from_col(CredentialSchema::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
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
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-ProofSchema-OrganisationId")
                            .from_tbl(ProofSchema::Table)
                            .from_col(ProofSchema::OrganisationId)
                            .to_tbl(Organisation::Table)
                            .to_col(Organisation::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(CredentialSchemaClaimSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::CredentialSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialSchemaClaimSchema::Order)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-CredentialSchema_ClaimSchema")
                            .col(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .col(CredentialSchemaClaimSchema::CredentialSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialSchema_ClaimSchema-ClaimId")
                            .from_tbl(CredentialSchemaClaimSchema::Table)
                            .from_col(CredentialSchemaClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-CredentialSchema_ClaimSchema-ProofId")
                            .from_tbl(CredentialSchemaClaimSchema::Table)
                            .from_col(CredentialSchemaClaimSchema::CredentialSchemaId)
                            .to_tbl(CredentialSchema::Table)
                            .to_col(CredentialSchema::Id),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ProofSchemaClaimSchema::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::ClaimSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::ProofSchemaId)
                            .char_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::Required)
                            .boolean()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ProofSchemaClaimSchema::Order)
                            .unsigned()
                            .not_null()
                            .default(0),
                    )
                    .primary_key(
                        Index::create()
                            .name("pk-ProofSchema_ClaimSchema")
                            .col(ProofSchemaClaimSchema::ClaimSchemaId)
                            .col(ProofSchemaClaimSchema::ProofSchemaId)
                            .primary(),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofSchema_ClaimSchema-ClaimId")
                            .from_tbl(ProofSchemaClaimSchema::Table)
                            .from_col(ProofSchemaClaimSchema::ClaimSchemaId)
                            .to_tbl(ClaimSchema::Table)
                            .to_col(ClaimSchema::Id),
                    )
                    .foreign_key(
                        ForeignKeyCreateStatement::new()
                            .name("fk-ProofSchema_ClaimSchema-ProofId")
                            .from_tbl(ProofSchemaClaimSchema::Table)
                            .from_col(ProofSchemaClaimSchema::ProofSchemaId)
                            .to_tbl(ProofSchema::Table)
                            .to_col(ProofSchema::Id),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(ProofSchemaClaimSchema::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(ProofSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(ClaimSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(CredentialSchema::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Organisation::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(Iden)]
pub enum CredentialSchema {
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
pub enum Format {
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
pub enum RevocationMethod {
    Table,
    #[iden = "STATUSLIST2021"]
    StatusList2021,
    #[iden = "LVVC"]
    Lvvc,
}

#[derive(Iden)]
pub enum ClaimSchema {
    Table,
    Id,
    Datatype,
    Key,
    CreatedDate,
    LastModified,
}

#[derive(Iden)]
pub enum Datatype {
    Table,
    #[iden = "STRING"]
    String,
    #[iden = "DATE"]
    Date,
    #[iden = "NUMBER"]
    Number,
}

#[derive(Iden)]
pub enum ProofSchema {
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
pub enum ProofSchemaClaimSchema {
    Table,
    ClaimSchemaId,
    ProofSchemaId,
    Required,
    Order,
}

#[derive(Iden)]
pub enum CredentialSchemaClaimSchema {
    Table,
    ClaimSchemaId,
    CredentialSchemaId,
    Required,
    Order,
}

#[derive(Iden)]
pub enum Organisation {
    Table,
    Id,
    CreatedDate,
    LastModified,
}
