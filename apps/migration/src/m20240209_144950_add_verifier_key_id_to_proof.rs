use sea_orm::{DbBackend, EntityTrait, FromQueryResult};
use sea_orm_migration::prelude::*;

use crate::{
    m20240110_000001_initial::{
        Claim, CustomDateTime, Did, Interaction, Key, KeyDid, Proof, ProofClaim,
        ProofRequestStateEnum, ProofSchema, ProofState,
    },
    m20240123_124653_proof_state_enum_rename_offered_to_requested::ProofRequestState,
    m20240209_144950_models::old_proof,
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(Debug, FromQueryResult)]
pub struct KeyDidQueryResult {
    key_id: String,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        match manager.get_database_backend() {
            DbBackend::MySql | DbBackend::Postgres => sane_migration(manager).await,
            DbBackend::Sqlite => sqlite_migration(manager).await,
        }
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "One way migration - cannot remove verifier key id".to_owned(),
        ))
    }
}

async fn sane_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .alter_table(
            Table::alter()
                .table(Proof::Table)
                .add_column(ColumnDef::new(ProofNew::VerifierKeyId).char_len(36))
                .add_foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-VerifierKeyId")
                        .from_tbl(Proof::Table)
                        .from_col(ProofNew::VerifierKeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id)
                        .get_foreign_key(),
                )
                .to_owned(),
        )
        .await?;

    add_verifier_key_to_proofs(manager.get_connection()).await
}

async fn sqlite_migration(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    let datetime = CustomDateTime(manager.get_database_backend());

    manager
        .create_table(
            Table::create()
                .table(ProofNew::Table)
                .col(
                    ColumnDef::new(Proof::Id)
                        .char_len(36)
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(Proof::CreatedDate)
                        .custom(datetime)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Proof::LastModified)
                        .custom(datetime)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Proof::IssuanceDate)
                        .custom(datetime)
                        .not_null(),
                )
                .col(ColumnDef::new(Proof::RedirectUri).string())
                .col(ColumnDef::new(Proof::VerifierDidId).char_len(36))
                .col(ColumnDef::new(Proof::HolderDidId).char_len(36))
                .col(ColumnDef::new(Proof::ProofSchemaId).char_len(36))
                .col(ColumnDef::new(Proof::Transport).string().not_null())
                .col(ColumnDef::new(ProofNew::VerifierKeyId).char_len(36))
                .col(ColumnDef::new(Proof::InteractionId).char_len(36))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-VerifierDidId")
                        .from_tbl(ProofNew::Table)
                        .from_col(Proof::VerifierDidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-HolderDidId")
                        .from_tbl(ProofNew::Table)
                        .from_col(Proof::HolderDidId)
                        .to_tbl(Did::Table)
                        .to_col(Did::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-ProofSchemaId")
                        .from_tbl(ProofNew::Table)
                        .from_col(Proof::ProofSchemaId)
                        .to_tbl(ProofSchema::Table)
                        .to_col(ProofSchema::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-VerifierKeyId")
                        .from_tbl(ProofNew::Table)
                        .from_col(ProofNew::VerifierKeyId)
                        .to_tbl(Key::Table)
                        .to_col(Key::Id),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-Proof-InteractionId")
                        .from_tbl(ProofNew::Table)
                        .from_col(Proof::InteractionId)
                        .to_tbl(Interaction::Table)
                        .to_col(Interaction::Id),
                )
                .to_owned(),
        )
        .await?;

    recreate_tables_with_new_name(manager, datetime).await?;

    let db = manager.get_connection();
    migrate_to_new_proof_table(db).await?;

    copy_data_to_new_tables(
        db,
        vec![
            ("proof_state", "proof_state_new"),
            ("proof_claim", "proof_claim_new"),
        ],
    )
    .await?;
    drop_and_rename_tables(
        manager,
        vec![
            (
                ProofState::Table.into_table_ref(),
                ProofStateNew::Table.into_table_ref(),
            ),
            (
                ProofClaim::Table.into_table_ref(),
                ProofClaimNew::Table.into_table_ref(),
            ),
            (
                Proof::Table.into_table_ref(),
                ProofNew::Table.into_table_ref(),
            ),
        ],
    )
    .await?;

    Ok(())
}

async fn add_verifier_key_to_proofs(db: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    let backend = db.get_database_backend();

    for old in old_proof::Entity::find().all(db).await? {
        let (_, verifier_key_id) = get_verifier_key_id(db, backend, &old).await?;

        db.execute(
            backend.build(
                Query::update()
                    .table(Proof::Table)
                    .value(ProofNew::VerifierKeyId, verifier_key_id)
                    .and_where(Expr::col(Proof::Id).eq(old.id)),
            ),
        )
        .await?;
    }

    Ok(())
}

async fn migrate_to_new_proof_table(db: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    let mut query = Query::insert()
        .into_table(ProofNew::Table)
        .columns([
            Proof::Id.into_iden(),
            Proof::CreatedDate.into_iden(),
            Proof::LastModified.into_iden(),
            Proof::IssuanceDate.into_iden(),
            Proof::Transport.into_iden(),
            Proof::RedirectUri.into_iden(),
            Proof::VerifierDidId.into_iden(),
            Proof::HolderDidId.into_iden(),
            Proof::ProofSchemaId.into_iden(),
            ProofNew::VerifierKeyId.into_iden(),
            Proof::InteractionId.into_iden(),
        ])
        .to_owned();

    let backend = db.get_database_backend();

    let old_proofs = old_proof::Entity::find().all(db).await?;
    if old_proofs.is_empty() {
        return Ok(());
    }

    for old in old_proofs {
        let (verifier_did_id, verifier_key_id) = get_verifier_key_id(db, backend, &old).await?;

        query
            .values([
                old.id.into(),
                old.created_date.into(),
                old.last_modified.into(),
                old.issuance_date.into(),
                old.transport.into(),
                old.redirect_uri.into(),
                verifier_did_id.into(),
                old.holder_did_id.into(),
                old.proof_schema_id.into(),
                verifier_key_id.into(),
                old.interaction_id.into(),
            ])
            .map_err(|e| DbErr::Migration(e.to_string()))?;
    }

    db.execute(backend.build(&query)).await?;

    Ok(())
}

async fn get_verifier_key_id(
    db: &SchemaManagerConnection<'_>,
    backend: DbBackend,
    old: &old_proof::Model,
) -> Result<(String, String), DbErr> {
    let verifier_did_id = old
        .verifier_did_id
        .to_owned()
        .ok_or(DbErr::Migration(format!(
            "Proof {} does not have verifier_did_id",
            old.id
        )))?;

    let verifier_key_id = KeyDidQueryResult::find_by_statement(
        backend.build(
            Query::select()
                .column(KeyDid::KeyId)
                .from(KeyDid::Table)
                .cond_where(
                    Expr::col(KeyDid::DidId)
                        .eq(verifier_did_id.to_owned())
                        .and(Expr::col(KeyDid::Role).eq("ASSERTION_METHOD")),
                ),
        ),
    )
    .one(db)
    .await?
    .ok_or(DbErr::Migration(format!(
        "Did {} does not have any related ASSERTION_METHOD keys",
        verifier_did_id
    )))?
    .key_id;
    Ok((verifier_did_id, verifier_key_id))
}

pub async fn drop_and_rename_tables(
    manager: &SchemaManager<'_>,
    tables: Vec<(TableRef, TableRef)>,
) -> Result<(), DbErr> {
    for (old, new) in tables {
        manager
            .drop_table(Table::drop().table(old.to_owned()).to_owned())
            .await?;
        manager
            .rename_table(Table::rename().table(new, old).to_owned())
            .await?;
    }
    Ok(())
}

pub async fn copy_data_to_new_tables(
    db: &SchemaManagerConnection<'_>,
    tables: Vec<(&str, &str)>,
) -> Result<(), DbErr> {
    for (from, to) in tables {
        let query = format!("INSERT INTO {to} SELECT * FROM {from};");
        db.execute_unprepared(&query).await?;
    }

    Ok(())
}

async fn recreate_tables_with_new_name(
    manager: &SchemaManager<'_>,
    datetime: CustomDateTime,
) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(ProofStateNew::Table)
                .col(ColumnDef::new(ProofState::ProofId).char_len(36).not_null())
                .col(
                    ColumnDef::new(ProofState::CreatedDate)
                        .custom(datetime)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofState::LastModified)
                        .custom(datetime)
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ProofState::State)
                        .enumeration(
                            ProofRequestStateEnum,
                            [
                                ProofRequestState::Created,
                                ProofRequestState::Pending,
                                ProofRequestState::Requested,
                                ProofRequestState::Accepted,
                                ProofRequestState::Rejected,
                                ProofRequestState::Error,
                            ],
                        )
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .name("pk-ProofState")
                        .col(ProofState::ProofId)
                        .col(ProofState::CreatedDate)
                        .primary(),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ProofState-ProofId")
                        .from_tbl(ProofStateNew::Table)
                        .from_col(ProofState::ProofId)
                        .to_tbl(ProofNew::Table)
                        .to_col(Proof::Id),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_table(
            Table::create()
                .table(ProofClaimNew::Table)
                .col(ColumnDef::new(ProofClaim::ClaimId).char_len(36).not_null())
                .col(ColumnDef::new(ProofClaim::ProofId).char_len(36).not_null())
                .primary_key(
                    Index::create()
                        .name("pk-ProofClaim")
                        .col(ProofClaim::ClaimId)
                        .col(ProofClaim::ProofId)
                        .primary(),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ProofClaim-ClaimId")
                        .from_tbl(ProofClaimNew::Table)
                        .from_col(ProofClaim::ClaimId)
                        .to_tbl(Claim::Table)
                        .to_col(Claim::Id),
                )
                .foreign_key(
                    ForeignKeyCreateStatement::new()
                        .name("fk-ProofClaim-ProofId")
                        .from_tbl(ProofClaimNew::Table)
                        .from_col(ProofClaim::ProofId)
                        .to_tbl(ProofNew::Table)
                        .to_col(Proof::Id),
                )
                .to_owned(),
        )
        .await?;
    Ok(())
}

#[derive(Iden)]
pub enum ProofNew {
    Table,
    VerifierKeyId,
}

#[derive(Iden)]
pub enum ProofStateNew {
    Table,
}

#[derive(Iden)]
pub enum ProofClaimNew {
    Table,
}
