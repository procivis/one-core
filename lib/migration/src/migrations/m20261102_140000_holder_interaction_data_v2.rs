//! Rewrites the holder data of OpenID4VCI issuance interactions into the shape that stores the
//! issuer and authorization server metadata as a whole, next to the issuance state.
//!
//! Older holder data stores a selection of metadata fields only. The metadata is reconstructed
//! from these and marked as `migrated`: anything outside of the selection is unknown. The
//! authorization server `issuer` was not stored, it is set to the credential issuer, as which it
//! has been used so far.
//!
//! The data was normalized by `m20261029_120000_normalize_holder_interaction_data`, this migration
//! restructures it. The display data (translations and logos) of the issuer and the credential
//! configurations is dropped: accepting an offer takes it from the current issuer metadata.

use sea_orm::{ConnectionTrait, FromQueryResult};
use sea_orm_migration::prelude::*;
use serde_json::{Map, Value, json};

#[derive(DeriveMigrationName)]
pub struct Migration;

const PAGE_SIZE: u64 = 200;

const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// Metadata of a credential configuration, as stored by older versions, without the display data
/// in `credential_metadata`
const CONFIGURATION_METADATA_FIELDS: [&str; 5] = [
    "format",
    "cryptographic_binding_methods_supported",
    "credential_signing_alg_values_supported",
    "proof_types_supported",
    "disclosure_policy",
];

/// State of a credential configuration
const CONFIGURATION_STATE_FIELDS: [&str; 3] = [
    "notification_ids",
    "credential_id",
    "credential_schema_format_id",
];

#[derive(FromQueryResult)]
struct InteractionRow {
    id: String,
    data: Vec<u8>,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let mut cursor = None;
        let mut migrated = 0;
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
                    Classification::HolderV1 => {}
                    Classification::UnreadableHolder => {
                        unreadable += 1;
                        continue;
                    }
                    Classification::Other => continue,
                }
                db.execute(
                    Query::update()
                        .table(Interaction::Table)
                        .value(
                            Interaction::Data,
                            serde_json::to_vec(&convert(data))
                                .map_err(|error| DbErr::Migration(error.to_string()))?,
                        )
                        .and_where(Expr::col(Interaction::Id).eq(&row.id)),
                )
                .await?;
                migrated += 1;
            }
        }
        tracing::info!(
            migrated,
            unreadable,
            "Migrated holder issuance interaction data, unreadable data of removed protocol versions is kept as is"
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
enum Classification {
    /// holder data in the shape before this migration
    HolderV1,
    /// holder data of removed protocol versions, not readable before this migration either
    UnreadableHolder,
    /// issuer data, authorization code flow data, or already migrated holder data
    Other,
}

fn classify(data: &Map<String, Value>) -> Classification {
    if !data.contains_key("issuer_url") || !data.contains_key("credential_endpoint") {
        return Classification::Other;
    }
    if !data.contains_key("protocol") {
        return Classification::UnreadableHolder;
    }
    Classification::HolderV1
}

/// Copies the non-null `fields` of `from` into `to`
fn copy_fields(from: &Map<String, Value>, to: &mut Map<String, Value>, fields: &[&str]) {
    for field in fields {
        if let Some(value) = from.get(*field).filter(|value| !value.is_null()) {
            to.insert((*field).to_owned(), value.clone());
        }
    }
}

fn convert(data: Map<String, Value>) -> Value {
    let get = |field: &str| data.get(field).filter(|value| !value.is_null());

    let mut configurations_supported = Map::new();
    let mut configuration_states = vec![];
    for configuration in get("credential_configurations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        let id = configuration
            .get("credential_configuration_id")
            .cloned()
            .unwrap_or_default();
        let mut metadata = Map::new();
        copy_fields(configuration, &mut metadata, &CONFIGURATION_METADATA_FIELDS);
        configurations_supported
            .insert(id.as_str().unwrap_or_default().to_string(), metadata.into());

        let mut state = Map::new();
        state.insert("credential_configuration_id".to_string(), id);
        copy_fields(configuration, &mut state, &CONFIGURATION_STATE_FIELDS);
        if state
            .get("notification_ids")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            state.remove("notification_ids");
        }
        configuration_states.push(Value::Object(state));
    }

    let grants = get("grants").and_then(Value::as_object);
    let continue_issuance = get("continue_issuance").and_then(Value::as_object);
    let authorization_server = grants
        .and_then(|grants| grants.values().next())
        .and_then(|grant| grant.get("authorization_server"))
        .or(continue_issuance.and_then(|data| data.get("authorization_server")))
        .filter(|server| server.is_string());

    let mut issuer_metadata = Map::new();
    issuer_metadata.insert(
        "credential_issuer".to_string(),
        get("issuer_url").cloned().unwrap_or_default(),
    );
    if let Some(authorization_server) = authorization_server {
        issuer_metadata.insert(
            "authorization_servers".to_string(),
            json!([authorization_server]),
        );
    }
    copy_fields(
        &data,
        &mut issuer_metadata,
        &[
            "credential_endpoint",
            "nonce_endpoint",
            "notification_endpoint",
            "credential_request_encryption",
            "credential_response_encryption",
        ],
    );
    if let Some(batch_size) = get("batch_size") {
        issuer_metadata.insert(
            "batch_credential_issuance".to_string(),
            json!({ "batch_size": batch_size }),
        );
    }
    issuer_metadata.insert(
        "credential_configurations_supported".to_string(),
        configurations_supported.into(),
    );

    let mut authorization_server_metadata = Map::new();
    authorization_server_metadata.insert(
        "issuer".to_string(),
        get("issuer_url").cloned().unwrap_or_default(),
    );
    copy_fields(
        &data,
        &mut authorization_server_metadata,
        &[
            "token_endpoint",
            "challenge_endpoint",
            "client_attestation_pop_signing_alg_values_supported",
            "dpop_signing_alg_values_supported",
        ],
    );
    if let Some(methods) = get("token_endpoint_auth_methods_supported").filter(|methods| {
        methods
            .as_array()
            .is_some_and(|methods| !methods.is_empty())
    }) {
        authorization_server_metadata.insert(
            "token_endpoint_auth_methods_supported".to_string(),
            methods.clone(),
        );
    }

    let mut state = Map::new();
    let grant = grants.and_then(|grants| {
        if let Some(code) = grants
            .get(PRE_AUTHORIZED_CODE_GRANT)
            .and_then(|grant| grant.get("pre-authorized_code"))
        {
            return Some(json!({ "type": "pre_authorized_code", "pre_authorized_code": code }));
        }
        let continue_issuance =
            continue_issuance.filter(|_| grants.contains_key("authorization_code"))?;
        let mut grant = Map::new();
        grant.insert("type".to_string(), "authorization_code".into());
        copy_fields(
            continue_issuance,
            &mut grant,
            &["authorization_code", "redirect_uri", "code_verifier"],
        );
        Some(grant.into())
    });
    if let Some(grant) = grant {
        state.insert("grant".to_string(), grant);
    }
    if let Some(client_id) = continue_issuance
        .and_then(|data| data.get("client_id"))
        .filter(|client_id| !client_id.is_null())
    {
        state.insert("client_id".to_string(), client_id.clone());
    }
    let mut tokens = Map::new();
    // the tokens are encrypted, their bytes are copied unchanged
    copy_fields(
        &data,
        &mut tokens,
        &[
            "access_token",
            "access_token_expires_at",
            "refresh_token",
            "refresh_token_expires_at",
        ],
    );
    state.insert("tokens".to_string(), tokens.into());
    let mut dpop = Map::new();
    if let Some(nonce) = get("dpop_nonce") {
        dpop.insert("nonce".to_string(), nonce.clone());
    }
    dpop.insert("disabled".to_string(), false.into());
    state.insert("dpop".to_string(), dpop.into());
    state.insert(
        "credential_configurations".to_string(),
        configuration_states.into(),
    );

    json!({
        "protocol": get("protocol"),
        "issuer_metadata": issuer_metadata,
        "authorization_server_metadata": authorization_server_metadata,
        "metadata_source": "migrated",
        "state": state,
    })
}

#[derive(DeriveIden)]
enum Interaction {
    Table,
    Id,
    Data,
    #[sea_orm(iden = "interaction_type")]
    Type,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    /// `path` within the folder of this migration
    fn fixture(path: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/migrations/m20261102_140000_holder_interaction_data_v2")
            .join(path);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn test_classify() {
        assert_eq!(
            Classification::HolderV1,
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
        assert_eq!(
            Classification::Other,
            classify(&object(json!({
                "protocol": "OPENID4VCI_FINAL1",
                "issuer_metadata": {},
                "state": {}
            })))
        );
    }

    #[test]
    fn test_convert_multiple_configurations() {
        assert_eq!(
            fixture("v2/multiple_configurations.json"),
            convert(object(fixture("v1/multiple_configurations.json")))
        );
    }

    #[test]
    fn test_convert_single_configuration() {
        assert_eq!(
            fixture("v2/single_configuration.json"),
            convert(object(fixture("v1/single_configuration.json")))
        );
    }
}
