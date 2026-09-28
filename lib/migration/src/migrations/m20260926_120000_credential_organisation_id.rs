use sea_orm::sea_query::IndexOrder;
use sea_orm_migration::prelude::*;
use sea_orm_migration::schema::{string, string_len_null, string_null, text_null};

use crate::datatype::{timestamp, timestamp_null, uuid_char, uuid_char_null};
use crate::foreign_key::{disable_foreign_key_checks, enable_foreign_key_checks};
use crate::migrations::m20260417_150300_initial::{
    BlobStorage, Certificate, Credential, CredentialSchema, FK_CREDENTIAL_CREDENTIAL_BLOB,
    FK_CREDENTIAL_CREDENTIAL_SCHEMA, FK_CREDENTIAL_HOLDER_IDENTIFIER, FK_CREDENTIAL_INTERACTION,
    FK_CREDENTIAL_ISSUER_CERTIFICATE, FK_CREDENTIAL_ISSUER_IDENTIFIER, FK_CREDENTIAL_KEY,
    FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB, INDEX_CREDENTIAL_CREATED_DATE,
    INDEX_CREDENTIAL_DELETED_AT, INDEX_CREDENTIAL_LIST, INDEX_CREDENTIAL_ROLE,
    INDEX_CREDENTIAL_STATE, INDEX_CREDENTIAL_SUSPEND_END_DATE, Identifier, Interaction, Key,
    Organisation,
};
use crate::migrations::m20260429_120000_credential_schema_multiformat::CredentialSchemaFormat;
use crate::migrations::m20260526_095002_credential_grouping::CredentialNew as CredentialWithType;
use crate::supported_db_type::{SupportedDbType, WithSupportedDbType};

#[derive(DeriveMigrationName)]
pub struct Migration;

const FK_CREDENTIAL_ORGANISATION: &str = "fk-Credential-OrganisationId";
const FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB: &str =
    "fk_credential_wallet_key_attestation_blob_id";
const FK_CREDENTIAL_CREDENTIAL: &str = "fk-Credential-Credential";
const FK_CREDENTIAL_FORMAT: &str = "fk-Credential-Format";
const INDEX_CREDENTIAL_TYPE: &str = "index-Credential-Type";
const INDEX_CREDENTIAL_ECOSYSTEM: &str = "index-Credential-Ecosystem";
const INDEX_CREDENTIAL_EARLIEST_EXPIRING_BATCH_ITEM: &str =
    "index-Credential-EarliestExpiringBatchItem";
const INDEX_CREDENTIAL_ORGANISATION_ID_DELETED_AT_ROLE_CREATED_DATE: &str =
    "index-Credential-OrganisationId-DeletedAt-Role-CreatedDate";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Credential::Table)
                    .add_column(uuid_char_null(CredentialNew::OrganisationId))
                    .to_owned(),
            )
            .await?;

        fill_organisation_id(manager).await?;

        disable_foreign_key_checks(manager).await?;
        if manager.supported_db_type() == SupportedDbType::Sqlite {
            organisation_id_not_null_sqlite(manager).await?;
        } else {
            organisation_id_not_null(manager).await?;
        }
        enable_foreign_key_checks(manager).await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum CredentialNew {
    Table,
    OrganisationId,
    WalletKeyAttestationBlobId,
    EmbeddedDisclosurePolicy,
    SubscriberInformation,
    Ecosystem,
    ExpiresAt,
    Format,
}

// one statement for all rows: dev has tens of thousands of organisations and schemas
async fn fill_organisation_id(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let organisation_of_schema = Query::select()
        .column((CredentialSchema::Table, CredentialSchema::OrganisationId))
        .from(CredentialSchema::Table)
        .and_where(
            Expr::col((CredentialSchema::Table, CredentialSchema::Id))
                .equals((Credential::Table, Credential::CredentialSchemaId)),
        )
        .to_owned();

    manager
        .exec_stmt(
            Query::update()
                .table(Credential::Table)
                .value(
                    CredentialNew::OrganisationId,
                    SimpleExpr::SubQuery(
                        None,
                        Box::new(organisation_of_schema.into_sub_query_statement()),
                    ),
                )
                .to_owned(),
        )
        .await?;

    Ok(())
}

/// Desk filters by organisation, deleted_at and role and sorts by creation date. `type` is in the
/// index only so its filter is checked in the index instead of in the row
fn organisation_index() -> IndexCreateStatement {
    Index::create()
        .name(INDEX_CREDENTIAL_ORGANISATION_ID_DELETED_AT_ROLE_CREATED_DATE)
        .table(Credential::Table)
        .col(CredentialNew::OrganisationId)
        .col(Credential::DeletedAt)
        .col(Credential::Role)
        .col(Credential::CreatedDate)
        .col(Credential::Id)
        .col(CredentialWithType::Type)
        .to_owned()
}

async fn organisation_id_not_null(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Credential::Table)
                .modify_column(uuid_char(CredentialNew::OrganisationId))
                .add_foreign_key(
                    TableForeignKey::new()
                        .name(FK_CREDENTIAL_ORGANISATION)
                        .from_tbl(Credential::Table)
                        .from_col(CredentialNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .to_owned(),
        )
        .await?;

    manager.create_index(organisation_index()).await?;

    // MariaDB merged these two single column indexes for the list query instead of using the one
    // above
    for index in [INDEX_CREDENTIAL_ROLE, INDEX_CREDENTIAL_DELETED_AT] {
        manager
            .drop_index(
                Index::drop()
                    .name(index)
                    .table(Credential::Table)
                    .to_owned(),
            )
            .await?;
    }

    Ok(())
}

// SQLite cannot make a column NOT NULL: rebuild the table, without the two single column indexes
async fn organisation_id_not_null_sqlite(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(CredentialNew::Table)
                .col(uuid_char(Credential::Id).primary_key())
                .col(timestamp(Credential::CreatedDate, manager))
                .col(timestamp(Credential::LastModified, manager))
                .col(timestamp_null(Credential::IssuanceDate, manager))
                .col(timestamp_null(Credential::DeletedAt, manager))
                .col(timestamp_null(Credential::SuspendEndDate, manager))
                .col(timestamp_null(CredentialWithType::ConsumedAt, manager))
                .col(timestamp_null(CredentialNew::ExpiresAt, manager))
                .col(string(Credential::Protocol))
                .col(string(Credential::Role))
                .col(string(Credential::State))
                .col(string(CredentialWithType::Type))
                .col(string_null(Credential::Profile))
                .col(string_null(CredentialNew::Ecosystem))
                .col(string_len_null(Credential::RedirectUri, 1000))
                .col(text_null(Credential::WebhookUrl))
                .col(text_null(CredentialNew::EmbeddedDisclosurePolicy))
                .col(text_null(CredentialNew::SubscriberInformation))
                .col(uuid_char(Credential::CredentialSchemaId))
                .col(uuid_char(CredentialNew::OrganisationId))
                .col(uuid_char_null(Credential::InteractionId))
                .col(uuid_char_null(Credential::HolderIdentifierId))
                .col(uuid_char_null(Credential::KeyId))
                .col(uuid_char_null(Credential::IssuerIdentifierId))
                .col(uuid_char_null(Credential::IssuerCertificateId))
                .col(uuid_char_null(Credential::CredentialBlobId))
                .col(uuid_char_null(Credential::WalletInstanceAttestationBlobId))
                .col(uuid_char_null(CredentialNew::WalletKeyAttestationBlobId))
                .col(uuid_char_null(CredentialWithType::ParentId))
                .col(uuid_char_null(CredentialNew::Format))
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL_SCHEMA)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialSchemaId)
                        .to_tbl(CredentialSchema::Table)
                        .to_col(CredentialSchema::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_ORGANISATION)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialNew::OrganisationId)
                        .to_tbl(Organisation::Table)
                        .to_col(Organisation::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_INTERACTION)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::InteractionId)
                        .to_tbl(Interaction::Table)
                        .to_col(Interaction::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_HOLDER_IDENTIFIER)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::HolderIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_KEY)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::KeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_ISSUER_IDENTIFIER)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerIdentifierId)
                        .to_tbl(Identifier::Table)
                        .to_col(Identifier::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_ISSUER_CERTIFICATE)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::IssuerCertificateId)
                        .to_tbl(Certificate::Table)
                        .to_col(Certificate::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL_BLOB)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::CredentialBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_WALLET_INSTANCE_ATTESTATION_BLOB)
                        .from_tbl(CredentialNew::Table)
                        .from_col(Credential::WalletInstanceAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_WALLET_KEY_ATTESTATION_BLOB)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialNew::WalletKeyAttestationBlobId)
                        .to_tbl(BlobStorage::Table)
                        .to_col(BlobStorage::Id)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_CREDENTIAL)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialWithType::ParentId)
                        .to_tbl(Credential::Table)
                        .to_col(Credential::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name(FK_CREDENTIAL_FORMAT)
                        .from_tbl(CredentialNew::Table)
                        .from_col(CredentialNew::Format)
                        .to_tbl(CredentialSchemaFormat::Table)
                        .to_col(CredentialSchemaFormat::Id),
                )
                .to_owned(),
        )
        .await?;

    let columns: Vec<DynIden> = vec![
        Credential::Id.into_iden(),
        Credential::CreatedDate.into_iden(),
        Credential::LastModified.into_iden(),
        Credential::IssuanceDate.into_iden(),
        Credential::DeletedAt.into_iden(),
        Credential::SuspendEndDate.into_iden(),
        CredentialWithType::ConsumedAt.into_iden(),
        CredentialNew::ExpiresAt.into_iden(),
        Credential::Protocol.into_iden(),
        Credential::Role.into_iden(),
        Credential::State.into_iden(),
        CredentialWithType::Type.into_iden(),
        Credential::Profile.into_iden(),
        CredentialNew::Ecosystem.into_iden(),
        Credential::RedirectUri.into_iden(),
        Credential::WebhookUrl.into_iden(),
        CredentialNew::EmbeddedDisclosurePolicy.into_iden(),
        CredentialNew::SubscriberInformation.into_iden(),
        Credential::CredentialSchemaId.into_iden(),
        CredentialNew::OrganisationId.into_iden(),
        Credential::InteractionId.into_iden(),
        Credential::HolderIdentifierId.into_iden(),
        Credential::KeyId.into_iden(),
        Credential::IssuerIdentifierId.into_iden(),
        Credential::IssuerCertificateId.into_iden(),
        Credential::CredentialBlobId.into_iden(),
        Credential::WalletInstanceAttestationBlobId.into_iden(),
        CredentialNew::WalletKeyAttestationBlobId.into_iden(),
        CredentialWithType::ParentId.into_iden(),
        CredentialNew::Format.into_iden(),
    ];

    manager
        .exec_stmt(
            Query::insert()
                .into_table(CredentialNew::Table)
                .columns(columns.clone())
                .select_from(
                    Query::select()
                        .from(Credential::Table)
                        .columns(columns)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Migration(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(Credential::Table).to_owned())
        .await?;

    manager
        .rename_table(
            Table::rename()
                .table(CredentialNew::Table, Credential::Table)
                .to_owned(),
        )
        .await?;

    let indexes = vec![
        Index::create()
            .name(INDEX_CREDENTIAL_LIST)
            .table(Credential::Table)
            .col(Credential::DeletedAt)
            .col(Credential::Role)
            .col(Credential::CreatedDate)
            .col(Credential::Id)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_CREATED_DATE)
            .table(Credential::Table)
            .col(Credential::CreatedDate)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_STATE)
            .table(Credential::Table)
            .col(Credential::State)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_SUSPEND_END_DATE)
            .table(Credential::Table)
            .col(Credential::SuspendEndDate)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_TYPE)
            .table(Credential::Table)
            .col(CredentialWithType::Type)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_ECOSYSTEM)
            .table(Credential::Table)
            .col(CredentialNew::Ecosystem)
            .to_owned(),
        Index::create()
            .name(INDEX_CREDENTIAL_EARLIEST_EXPIRING_BATCH_ITEM)
            .table(Credential::Table)
            .col(CredentialWithType::ConsumedAt)
            .col(Credential::State)
            .col(CredentialWithType::ParentId)
            .col(CredentialNew::Format)
            .col(CredentialWithType::Type)
            .col(Credential::DeletedAt)
            .col((CredentialNew::ExpiresAt, IndexOrder::Asc))
            .col((Credential::Id, IndexOrder::Desc))
            .to_owned(),
        organisation_index(),
    ];
    for index in indexes {
        manager.create_index(index).await?;
    }

    Ok(())
}
