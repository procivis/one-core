//! Normalizes older holder data of OpenID4VCI issuance interactions:
//! * a single credential configuration stored at the top level is moved into
//!   `credential_configurations`
//! * a single `notification_id` becomes `notification_ids`
//! * the single configuration of data stored before the association was recorded is associated
//!   with its issued credential (`credential_id`) and the exact format of its items
//!   (`credential_schema_format_id`)
//!
//! Interactions with several top-level credentials stay unassociated: older versions stored the
//! non-mdoc copies of a batch as separate `SINGLE` credentials, which are not refreshed anyway.

use std::collections::BTreeSet;

use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use serde_json::{Map, Value};

#[derive(DeriveMigrationName)]
pub struct Migration;

const PAGE_SIZE: u64 = 200;

/// Fields of a credential configuration, stored at the top level by older versions
const CONFIGURATION_FIELDS: [&str; 11] = [
    "credential_configuration_id",
    "format",
    "cryptographic_binding_methods_supported",
    "credential_signing_alg_values_supported",
    "proof_types_supported",
    "credential_metadata",
    "disclosure_policy",
    "notification_id",
    "notification_ids",
    "credential_id",
    "credential_schema_format_id",
];

#[derive(FromQueryResult)]
struct InteractionRow {
    id: String,
    data: Vec<u8>,
}

#[derive(FromQueryResult)]
struct CredentialRow {
    id: String,
    r#type: String,
    format: Option<String>,
}

#[derive(FromQueryResult)]
struct FormatRow {
    format: String,
}

/// Credential issued for the single configuration of an interaction stored before the
/// association was recorded
pub(crate) struct IssuedCredential {
    pub credential_id: String,
    pub credential_schema_format_id: Option<String>,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let mut cursor = None;
        let mut normalized = 0;
        let mut unreadable = 0;
        loop {
            let rows = load_page(db, cursor.as_deref()).await?;
            let Some(last) = rows.last() else {
                break;
            };
            cursor = Some(last.id.clone());
            for row in rows {
                let Ok(Value::Object(data)) = serde_json::from_slice::<Value>(&row.data) else {
                    continue;
                };
                match classify(&data) {
                    Classification::Holder => {}
                    Classification::UnreadableHolder => {
                        unreadable += 1;
                        continue;
                    }
                    Classification::Other => continue,
                }
                let mut normalized_data = normalize_configurations(data.clone());
                if needs_issued_credential(&normalized_data) {
                    let issued = find_issued_credential(db, &row.id).await?;
                    associate_issued_credential(&mut normalized_data, issued);
                }
                if normalized_data == data {
                    continue;
                }
                db.execute(
                    Query::update()
                        .table(Interaction::Table)
                        .value(
                            Interaction::Data,
                            serde_json::to_vec(&normalized_data)
                                .map_err(|error| DbErr::Migration(error.to_string()))?,
                        )
                        .and_where(Expr::col(Interaction::Id).eq(&row.id)),
                )
                .await?;
                normalized += 1;
            }
        }
        tracing::info!(
            normalized,
            unreadable,
            "Normalized holder issuance interaction data, unreadable data of removed protocol versions is kept as is"
        );
        Ok(())
    }
}

async fn load_page(
    db: &impl ConnectionTrait,
    cursor: Option<&str>,
) -> Result<Vec<InteractionRow>, DbErr> {
    let mut query = Query::select();
    query
        .columns([Interaction::Id, Interaction::Data])
        .from(Interaction::Table)
        .and_where(Expr::col(Interaction::Type).eq("ISSUANCE"))
        .and_where(Expr::col(Interaction::Data).is_not_null())
        .order_by(Interaction::Id, Order::Asc)
        .limit(PAGE_SIZE);
    if let Some(id) = cursor {
        query.and_where(Expr::col(Interaction::Id).gt(id));
    }
    InteractionRow::find_by_statement(db.get_database_backend().build(&query))
        .all(db)
        .await
}

#[derive(Debug, PartialEq)]
pub(crate) enum Classification {
    /// holder data
    Holder,
    /// holder data of removed protocol versions, not readable before this migration either
    UnreadableHolder,
    /// issuer data or authorization code flow data
    Other,
}

pub(crate) fn classify(data: &Map<String, Value>) -> Classification {
    if !data.contains_key("issuer_url") || !data.contains_key("credential_endpoint") {
        return Classification::Other;
    }
    if !data.contains_key("protocol") {
        return Classification::UnreadableHolder;
    }
    Classification::Holder
}

/// Moves a single configuration stored at the top level into `credential_configurations`, and
/// replaces `notification_id` by `notification_ids`
pub(crate) fn normalize_configurations(mut data: Map<String, Value>) -> Map<String, Value> {
    let configurations = match data.remove("credential_configurations") {
        Some(Value::Array(configurations)) => configurations,
        _ => {
            let mut configuration = Map::new();
            for field in CONFIGURATION_FIELDS {
                if let Some(value) = data.remove(field) {
                    configuration.insert(field.to_owned(), value);
                }
            }
            vec![Value::Object(configuration)]
        }
    };
    let configurations = configurations
        .into_iter()
        .map(|configuration| match configuration {
            Value::Object(configuration) => {
                Value::Object(normalize_notification_ids(configuration))
            }
            other => other,
        })
        .collect();
    data.insert(
        "credential_configurations".to_owned(),
        Value::Array(configurations),
    );
    data
}

fn normalize_notification_ids(mut configuration: Map<String, Value>) -> Map<String, Value> {
    let Some(notification_ids) = configuration
        .remove("notification_id")
        .filter(|value| !value.is_null())
        .or_else(|| configuration.get("notification_ids").cloned())
    else {
        return configuration;
    };
    let notification_ids = match notification_ids {
        Value::String(id) => Value::Array(vec![Value::String(id)]),
        other => other,
    };
    configuration.insert("notification_ids".to_owned(), notification_ids);
    configuration
}

fn single_configuration(data: &Map<String, Value>) -> Option<&Map<String, Value>> {
    match data.get("credential_configurations") {
        Some(Value::Array(configurations)) if configurations.len() == 1 => {
            configurations.first().and_then(Value::as_object)
        }
        _ => None,
    }
}

/// The single configuration of older data has no association with its credential
fn needs_issued_credential(data: &Map<String, Value>) -> bool {
    single_configuration(data).is_some_and(|configuration| {
        configuration
            .get("credential_id")
            .is_none_or(Value::is_null)
            || configuration
                .get("credential_schema_format_id")
                .is_none_or(Value::is_null)
    })
}

/// Fills in the missing association of the single configuration, an existing one is kept
pub(crate) fn associate_issued_credential(
    data: &mut Map<String, Value>,
    issued: Option<IssuedCredential>,
) {
    let Some(issued) = issued else {
        return;
    };
    let Some(Value::Array(configurations)) = data.get_mut("credential_configurations") else {
        return;
    };
    let [Value::Object(configuration)] = configurations.as_mut_slice() else {
        return;
    };
    let credential_id = Value::String(issued.credential_id);
    let current = configuration
        .get("credential_id")
        .filter(|value| !value.is_null());
    if current.is_some_and(|current| current != &credential_id) {
        return;
    }
    configuration.insert("credential_id".to_owned(), credential_id);
    if let Some(format) = issued.credential_schema_format_id
        && configuration
            .get("credential_schema_format_id")
            .is_none_or(Value::is_null)
    {
        configuration.insert(
            "credential_schema_format_id".to_owned(),
            Value::String(format),
        );
    }
}

async fn find_issued_credential(
    db: &impl ConnectionTrait,
    interaction_id: &str,
) -> Result<Option<IssuedCredential>, DbErr> {
    let credentials = CredentialRow::find_by_statement(
        db.get_database_backend().build(
            Query::select()
                .columns([Credential::Id, Credential::Type, Credential::Format])
                .from(Credential::Table)
                .and_where(Expr::col(Credential::InteractionId).eq(interaction_id))
                .and_where(Expr::col(Credential::Role).eq("HOLDER"))
                .and_where(Expr::col(Credential::Type).is_in(["SINGLE", "BATCH_PARENT"]))
                .and_where(Expr::col(Credential::DeletedAt).is_null()),
        ),
    )
    .all(db)
    .await?;
    let [credential] = credentials.as_slice() else {
        return Ok(None);
    };
    let format = if credential.r#type == "BATCH_PARENT" {
        // the format of a batch is the one of its items
        let formats: BTreeSet<_> = FormatRow::find_by_statement(
            db.get_database_backend().build(
                Query::select()
                    .column(Credential::Format)
                    .from(Credential::Table)
                    .and_where(Expr::col(Credential::ParentId).eq(&credential.id))
                    .and_where(Expr::col(Credential::Type).eq("BATCH_ITEM"))
                    .and_where(Expr::col(Credential::DeletedAt).is_null())
                    .and_where(Expr::col(Credential::Format).is_not_null()),
            ),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.format)
        .collect();
        match <[String; 1]>::try_from(formats.into_iter().collect::<Vec<_>>()) {
            Ok([format]) => Some(format),
            Err(_) => None,
        }
    } else {
        credential.format.clone()
    };
    Ok(Some(IssuedCredential {
        credential_id: credential.id.clone(),
        credential_schema_format_id: format,
    }))
}

#[derive(DeriveIden)]
enum Interaction {
    Table,
    Id,
    Data,
    #[sea_orm(iden = "interaction_type")]
    Type,
}

#[derive(DeriveIden)]
enum Credential {
    Table,
    Id,
    InteractionId,
    ParentId,
    Role,
    Type,
    Format,
    DeletedAt,
}

#[cfg(test)]
mod test {
    use serde_json::json;
    use similar_asserts::assert_eq;

    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn issued() -> Option<IssuedCredential> {
        Some(IssuedCredential {
            credential_id: "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d".to_string(),
            credential_schema_format_id: Some("2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e".to_string()),
        })
    }

    #[test]
    fn test_classify() {
        assert_eq!(
            Classification::Holder,
            classify(&object(json!({
                "issuer_url": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "protocol": "OPENID4VCI_FINAL1"
            })))
        );
        assert_eq!(
            Classification::UnreadableHolder,
            classify(&object(json!({
                "issuer_url": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential"
            })))
        );
        assert_eq!(
            Classification::Other,
            classify(&object(json!({
                "pre_authorized_code_used": true,
                "access_token_hash": []
            })))
        );
        assert_eq!(
            Classification::Other,
            classify(&object(
                json!({ "request": {}, "code_verifier": "verifier" })
            ))
        );
    }

    #[test]
    fn test_normalize_single_configuration_at_top_level() {
        let mut data = normalize_configurations(object(json!({
            "issuer_url": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "token_endpoint_auth_methods_supported": [],
            "protocol": "OPENID4VCI_FINAL1",
            "credential_configuration_id": "sd_jwt",
            "format": "dc+sd-jwt",
            "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } },
            "notification_id": "notification"
        })));
        assert!(needs_issued_credential(&data));
        associate_issued_credential(&mut data, issued());

        assert_eq!(
            object(json!({
                "issuer_url": "https://issuer.example.com",
                "credential_endpoint": "https://issuer.example.com/credential",
                "token_endpoint_auth_methods_supported": [],
                "protocol": "OPENID4VCI_FINAL1",
                "credential_configurations": [{
                    "credential_configuration_id": "sd_jwt",
                    "format": "dc+sd-jwt",
                    "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256"] } },
                    "notification_ids": ["notification"],
                    "credential_id": "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
                    "credential_schema_format_id": "2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e"
                }]
            })),
            data
        );
    }

    #[test]
    fn test_normalize_keeps_multiple_configurations() {
        let data = object(json!({
            "issuer_url": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "protocol": "OPENID4VCI_FINAL1",
            "credential_configurations": [
                {
                    "credential_configuration_id": "jwt",
                    "format": "jwt_vc_json",
                    "notification_ids": ["n1", "n2"],
                    "credential_id": "6f7c2c8e-7f0e-4c4e-9b0a-6a3f2b1c0d9e",
                    "credential_schema_format_id": "0c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
                },
                { "credential_configuration_id": "mdoc", "format": "mso_mdoc" }
            ]
        }));

        let normalized = normalize_configurations(data.clone());

        assert_eq!(data, normalized);
        assert!(!needs_issued_credential(&normalized));
    }

    #[test]
    fn test_normalize_notification_id_of_configuration_entry() {
        let data = normalize_configurations(object(json!({
            "issuer_url": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "protocol": "OPENID4VCI_FINAL1",
            "credential_configurations": [
                { "credential_configuration_id": "jwt", "format": "jwt_vc_json", "notification_id": "n1" },
                { "credential_configuration_id": "mdoc", "format": "mso_mdoc", "notification_id": null }
            ]
        })));

        assert_eq!(
            json!([
                { "credential_configuration_id": "jwt", "format": "jwt_vc_json", "notification_ids": ["n1"] },
                { "credential_configuration_id": "mdoc", "format": "mso_mdoc" }
            ]),
            data["credential_configurations"]
        );
    }

    #[test]
    fn test_associate_keeps_existing_association_of_single_configuration() {
        let mut data = normalize_configurations(object(json!({
            "issuer_url": "https://issuer.example.com",
            "credential_endpoint": "https://issuer.example.com/credential",
            "protocol": "OPENID4VCI_FINAL1",
            "credential_configurations": [{
                "credential_configuration_id": "sd_jwt",
                "format": "dc+sd-jwt",
                "credential_id": "other"
            }]
        })));
        assert!(needs_issued_credential(&data));

        associate_issued_credential(&mut data, issued());

        assert_eq!(
            json!([{ "credential_configuration_id": "sd_jwt", "format": "dc+sd-jwt", "credential_id": "other" }]),
            data["credential_configurations"]
        );
    }
}
