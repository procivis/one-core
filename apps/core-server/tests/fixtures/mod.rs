use core_server::Config;
use one_core::model::proof::ProofStateEnum;
use shared_types::{DidId, DidValue};
use sql_data_provider::{self, test_utilities::*, DbConn};
use std::str::FromStr;
use uuid::Uuid;

pub fn create_config(core_base_url: impl Into<String>) -> Config {
    Config {
        config_file: "../../config.yml".to_string(),
        database_url: "sqlite::memory:".to_string(),
        auth_token: "test".to_string(),
        core_base_url: core_base_url.into(),
        server_ip: None,
        server_port: None,
        trace_json: None,
        sentry_dsn: None,
        sentry_environment: None,
    }
}

pub async fn create_db(config: &Config) -> DbConn {
    sql_data_provider::db_conn(&config.database_url).await
}

pub async fn create_organisation(db_conn: &DbConn) -> String {
    insert_organisation_to_database(db_conn, None)
        .await
        .unwrap()
}

pub async fn create_did_key(db_conn: &DbConn, organisation_id: &str) -> DidId {
    let did_id = Uuid::new_v4().to_string();

    let _key_id = insert_key_to_database(db_conn, organisation_id)
        .await
        .unwrap();

    insert_did(
        db_conn,
        "test-did-key",
        DidValue::from_str(&did_id).unwrap(),
        organisation_id,
    )
    .await
    .unwrap()
}

pub async fn create_credential_schema(
    db_conn: &DbConn,
    name: &str,
    organisation_id: &str,
    claims: &Vec<(Uuid, &str, bool, u32, &str)>,
) -> String {
    let credential_schema_id =
        insert_credential_schema_to_database(db_conn, None, organisation_id, name, "JWT", "NONE")
            .await
            .unwrap();

    insert_many_claims_schema_to_database(db_conn, &credential_schema_id, claims)
        .await
        .unwrap();
    credential_schema_id
}

#[allow(clippy::too_many_arguments)]
pub async fn create_proof(
    db_conn: &DbConn,
    verifier_did_id: DidId,
    holder_did_id: Option<DidId>,
    proof_schema_id: Option<String>,
    state: ProofStateEnum,
    transport: &str,
    claims: &Vec<(Uuid, Uuid, String)>,
    interaction_id: Option<String>,
) -> String {
    insert_proof_request_to_database_with_claims(
        db_conn,
        verifier_did_id,
        holder_did_id,
        proof_schema_id,
        state,
        transport,
        claims,
        interaction_id,
    )
    .await
    .unwrap()
}

pub async fn create_interaction(db_conn: &DbConn, host: &str, data: &Vec<u8>) -> String {
    insert_interaction(db_conn, host, data).await.unwrap()
}

pub async fn create_credentials_with_claims(
    db_conn: &DbConn,
    credential_schema_id: &str,
    did_id: DidId,
    transport: &str,
    claims: &Vec<(Uuid, String)>,
) -> String {
    let credential_id = insert_credential(db_conn, credential_schema_id, transport, did_id)
        .await
        .unwrap();
    insert_many_credential_claims_to_database(db_conn, &credential_id, claims)
        .await
        .unwrap();

    credential_id
}
