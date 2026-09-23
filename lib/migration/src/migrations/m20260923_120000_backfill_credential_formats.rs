use std::collections::{BTreeSet, HashMap};

use ct_codecs::{Base64UrlSafe, Base64UrlSafeNoPadding, Decoder};
use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use serde_json::Value;

#[derive(DeriveMigrationName)]
pub struct Migration;

const PAGE_SIZE: u64 = 200;

struct FormatAssignment {
    credential_id: String,
    credential_schema_id: String,
    format: String,
}

#[derive(FromQueryResult)]
struct CredentialRow {
    id: String,
    credential_schema_id: String,
    credential_blob_id: Option<String>,
}

#[derive(FromQueryResult)]
struct FormatRow {
    id: String,
    credential_schema_id: String,
    format: String,
}

#[derive(FromQueryResult)]
struct BlobRow {
    id: String,
    value: Vec<u8>,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        tracing::info!("Starting credential format backfill");
        process_pages(db).await?;
        clear_parent_formats(db).await
    }
}

async fn process_pages(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let mut cursor = None;
    let mut page = 0;
    let mut total_updated = 0;
    loop {
        let credentials = load_credential_page(db, cursor.as_deref()).await?;
        let Some(last) = credentials.last() else {
            tracing::info!(
                pages = page,
                total_updated,
                "Finished credential format pages"
            );
            return Ok(());
        };
        page += 1;
        tracing::info!(
            page,
            credentials = credentials.len(),
            last_credential_id = %last.id,
            "Processing credential format page"
        );
        cursor = Some(last.id.clone());
        let assignments = resolve_page(db, &credentials).await.inspect_err(|error| {
            tracing::error!(page, %error, "Failed to resolve credential format page");
        })?;
        let updated = apply_assignments(db, &assignments).await?;
        total_updated += updated;
        tracing::info!(
            page,
            updated,
            total_updated,
            "Applied credential format page"
        );
    }
}

async fn load_credential_page(
    db: &impl ConnectionTrait,
    cursor: Option<&str>,
) -> Result<Vec<CredentialRow>, DbErr> {
    let mut query = Query::select();
    query
        .columns([Credential::Id, Credential::SchemaId, Credential::BlobId])
        .from(Credential::Table)
        .and_where(Expr::col(Credential::Type).is_in(["SINGLE", "BATCH_ITEM"]))
        .and_where(Expr::col(Credential::Format).is_null())
        .order_by(Credential::Id, Order::Asc)
        .limit(PAGE_SIZE);
    if let Some(id) = cursor {
        query.and_where(Expr::col(Credential::Id).gt(id));
    }
    CredentialRow::find_by_statement(db.get_database_backend().build(&query))
        .all(db)
        .await
}

async fn load_schema_formats(
    db: &impl ConnectionTrait,
    credentials: &[CredentialRow],
) -> Result<HashMap<String, Vec<FormatRow>>, DbErr> {
    let schema_ids: BTreeSet<_> = credentials
        .iter()
        .map(|row| &row.credential_schema_id)
        .collect();
    let rows = FormatRow::find_by_statement(
        db.get_database_backend().build(
            Query::select()
                .columns([
                    CredentialSchemaFormat::Id,
                    CredentialSchemaFormat::CredentialSchemaId,
                    CredentialSchemaFormat::Format,
                ])
                .from(CredentialSchemaFormat::Table)
                .and_where(Expr::col(CredentialSchemaFormat::CredentialSchemaId).is_in(schema_ids)),
        ),
    )
    .all(db)
    .await?;
    let mut formats: HashMap<String, Vec<FormatRow>> = HashMap::new();
    for row in rows {
        formats
            .entry(row.credential_schema_id.clone())
            .or_default()
            .push(row);
    }
    Ok(formats)
}

async fn load_blobs(
    db: &impl ConnectionTrait,
    credentials: &[CredentialRow],
    formats: &HashMap<String, Vec<FormatRow>>,
) -> Result<HashMap<String, Vec<u8>>, DbErr> {
    // Single-format schemas do not require a blob, including pending or deleted credentials.
    let ids: BTreeSet<_> = credentials
        .iter()
        .filter(|row| {
            formats
                .get(&row.credential_schema_id)
                .is_some_and(|formats| formats.len() > 1)
        })
        .filter_map(|row| row.credential_blob_id.as_ref())
        .collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = BlobRow::find_by_statement(
        db.get_database_backend().build(
            Query::select()
                .columns([BlobStorage::Id, BlobStorage::Value])
                .from(BlobStorage::Table)
                .and_where(Expr::col(BlobStorage::Id).is_in(ids))
                .and_where(Expr::col(BlobStorage::Type).eq("CREDENTIAL")),
        ),
    )
    .all(db)
    .await?;
    Ok(rows.into_iter().map(|row| (row.id, row.value)).collect())
}

async fn resolve_page(
    db: &impl ConnectionTrait,
    credentials: &[CredentialRow],
) -> Result<Vec<FormatAssignment>, DbErr> {
    let formats = load_schema_formats(db, credentials).await?;
    let blobs = load_blobs(db, credentials, &formats).await?;
    credentials
        .iter()
        .map(|row| {
            let schema_formats = formats
                .get(&row.credential_schema_id)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let blob = row.credential_blob_id.as_ref().and_then(|id| blobs.get(id));
            resolve_format(schema_formats, blob.map(Vec::as_slice))
                .map(|format| FormatAssignment {
                    credential_id: row.id.clone(),
                    credential_schema_id: row.credential_schema_id.clone(),
                    format: format.to_owned(),
                })
                .map_err(|reason| {
                    DbErr::Migration(format!(
                        "Cannot backfill credential {} (schema {}): {reason}",
                        row.id, row.credential_schema_id,
                    ))
                })
        })
        .collect()
}

fn resolve_format<'a>(
    formats: &'a [FormatRow],
    blob: Option<&[u8]>,
) -> Result<&'a str, &'static str> {
    match formats {
        [] => return Err("credential schema has no formats"),
        [format] => return Ok(&format.id),
        _ => {}
    }
    let blob = blob.ok_or("multiple schema formats but credential blob is missing")?;
    let detected = detect_blob_format(blob);
    let mut matches = formats.iter().filter(|format| {
        // Known configuration aliases share a wire format; never choose between two
        // schema options with the same wire format or infer arbitrary custom aliases.
        let family = match format.format.as_str() {
            "SD_JWT_VC_SWIYU" => "SD_JWT_VC",
            "MDOC_SHORT_EXPIRY" => "MDOC",
            other => other,
        };
        family == detected
    });
    let format = matches
        .next()
        .ok_or("blob format does not match any schema format")?;
    if matches.next().is_some() {
        return Err("blob matches multiple schema formats");
    }
    Ok(&format.id)
}

// Identify the most likely serialization without validating the credential.
fn detect_blob_format(blob: &[u8]) -> &'static str {
    let Ok(token) = std::str::from_utf8(blob) else {
        return "MDOC";
    };
    let token = token.trim();
    if token.starts_with('{') {
        json_ld_format(&serde_json::from_str::<Value>(token).unwrap_or_default())
    } else if token.contains('.') || token.contains('~') {
        jwt_format(token)
    } else {
        "MDOC"
    }
}

fn json_ld_format(value: &Value) -> &'static str {
    let proof = value.get("proof").unwrap_or(&Value::Null);
    let proofs = proof
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(std::slice::from_ref(proof));
    if proofs
        .iter()
        .any(|proof| proof.get("cryptosuite").and_then(Value::as_str) == Some("bbs-2023"))
    {
        "JSON_LD_BBSPLUS"
    } else {
        "JSON_LD_CLASSIC"
    }
}

fn jwt_format(token: &str) -> &'static str {
    let payload = token
        .split('~')
        .next()
        .and_then(|jwt| jwt.split('.').nth(1))
        .and_then(decode_base64)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    if payload
        .as_ref()
        .and_then(|payload| payload.get("vct"))
        .is_some()
    {
        "SD_JWT_VC"
    } else if token.contains('~') {
        "SD_JWT"
    } else {
        "JWT"
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    Base64UrlSafeNoPadding::decode_to_vec(value, None)
        .or_else(|_| Base64UrlSafe::decode_to_vec(value, None))
        .ok()
}

async fn apply_assignments(
    db: &impl ConnectionTrait,
    assignments: &[FormatAssignment],
) -> Result<u64, DbErr> {
    let mut updated = 0;
    // Individual writes identify the exact failing entity. Completed assignments are
    // safe to retain: retries only select credentials whose format is still missing.
    for assignment in assignments {
        let result = db
            .execute(
                Query::update()
                    .table(Credential::Table)
                    .value(Credential::Format, assignment.format.clone())
                    .and_where(Expr::col(Credential::Id).eq(&assignment.credential_id))
                    .and_where(Expr::col(Credential::Format).is_null()),
            )
            .await
            .map_err(|error| {
                tracing::error!(
                    credential_id = %assignment.credential_id,
                    credential_schema_id = %assignment.credential_schema_id,
                    format_id = %assignment.format,
                    %error,
                    "Failed to apply credential format"
                );
                DbErr::Migration(format!(
                    "Cannot update credential {} (schema {}) to format {}: {error}",
                    assignment.credential_id, assignment.credential_schema_id, assignment.format,
                ))
            })?;
        updated += result.rows_affected();
    }
    Ok(updated)
}

async fn clear_parent_formats(db: &impl ConnectionTrait) -> Result<(), DbErr> {
    let result = db
        .execute(
            Query::update()
                .table(Credential::Table)
                .value(Credential::Format, Option::<String>::None)
                .and_where(Expr::col(Credential::Type).eq("BATCH_PARENT"))
                .and_where(Expr::col(Credential::Format).is_not_null()),
        )
        .await
        .inspect_err(|error| {
            tracing::error!(%error, "Failed to clear batch parent formats");
        })?;
    tracing::info!(
        updated = result.rows_affected(),
        "Cleared batch parent formats"
    );
    Ok(())
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
    #[sea_orm(iden = "credential_schema_id")]
    SchemaId,
    #[sea_orm(iden = "credential_blob_id")]
    BlobId,
    Type,
    Format,
}

#[derive(DeriveIden)]
enum CredentialSchemaFormat {
    Table,
    Id,
    CredentialSchemaId,
    Format,
}

#[derive(DeriveIden)]
enum BlobStorage {
    Table,
    Id,
    Value,
    Type,
}
