use one_core::model::claim::Claim;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::proof::{Proof, ProofStateEnum};
use one_core::repository::error::DataLayerError;
use one_core::{
    config::data_structure::{
        DatatypeEntity, DatatypeType, DidEntity, ExchangeEntity, FormatEntity, RevocationEntity,
        TranslatableString,
    },
    model::interaction::InteractionId,
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::{DidId, DidValue};
use std::collections::HashMap;
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    db_conn,
    entity::{
        claim, claim_schema, credential, credential_claim, credential_schema,
        credential_schema_claim_schema, credential_state, did, interaction, key, key_did,
        organisation, proof, proof_claim, proof_schema, proof_schema_claim_schema,
        proof_state::{self, ProofRequestState},
    },
    DataLayer,
};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub async fn insert_credential(
    db: &DatabaseConnection,
    credential_schema_id: &str,
    state: CredentialStateEnum,
    protocol: &str,
    did_id: DidId,
) -> Result<String, DbErr> {
    let now = OffsetDateTime::now_utc();

    let credential = credential::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        credential_schema_id: Set(credential_schema_id.to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        issuance_date: Set(now),
        deleted_at: Set(None),
        transport: Set(protocol.to_owned()),
        credential: Set(vec![0, 0, 0, 0]),
        issuer_did_id: Set(Some(did_id)),
        holder_did_id: Set(None),
        interaction_id: Set(None),
        revocation_list_id: Set(None),
        key_id: Set(None),
    }
    .insert(db)
    .await?;

    credential_state::ActiveModel {
        credential_id: Set(credential.id.to_owned()),
        created_date: Set(now),
        state: Set(state.into()),
    }
    .insert(db)
    .await?;

    Ok(credential.id)
}

pub async fn insert_credential_schema_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    organisation_id: &str,
    name: &str,
    format: &str,
    revocation_method: &str,
) -> Result<String, DbErr> {
    let schema = credential_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        format: Set(format.to_owned()),
        name: Set(name.to_owned()),
        revocation_method: Set(revocation_method.to_owned()),
        organisation_id: Set(organisation_id.to_owned()),

        deleted_at: Set(deleted_at),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

#[allow(clippy::ptr_arg)]
pub async fn insert_many_claims_schema_to_database(
    database: &DatabaseConnection,
    credential_schema_id: &str,
    claims: &Vec<(Uuid, &str, bool, u32, &str)>,
) -> Result<(), DbErr> {
    for (id, key, required, order, datatype) in claims {
        claim_schema::ActiveModel {
            id: Set(id.to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set(key.to_string()),
            datatype: Set(datatype.to_string()),
        }
        .insert(database)
        .await?;

        credential_schema_claim_schema::ActiveModel {
            claim_schema_id: Set(id.to_string()),
            credential_schema_id: Set(credential_schema_id.to_owned()),
            required: Set(*required),
            order: Set(*order),
        }
        .insert(database)
        .await?;
    }
    Ok(())
}

#[allow(clippy::ptr_arg)]
#[allow(dead_code)]
pub async fn insert_many_credential_claims_to_database(
    database: &DatabaseConnection,
    credential_id: &str,
    claims: &Vec<(Uuid, Uuid, String)>,
) -> Result<(), DbErr> {
    let claims_to_insert =
        claims
            .iter()
            .map(|(claim_schema_id, claim_id, value)| claim::ActiveModel {
                // Just for tests id of a claim will be the same as id for a schema it instantiates
                id: Set(claim_id.to_string()),
                claim_schema_id: Set(claim_schema_id.to_string()),
                value: Set(value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
            });

    let credential_claims =
        claims.iter().map(
            |(_claim_schema_id, claim_id, ..)| credential_claim::ActiveModel {
                claim_id: Set(claim_id.to_string()),
                credential_id: Set(credential_id.to_owned()),
            },
        );

    claim::Entity::insert_many(claims_to_insert)
        .exec(database)
        .await?;

    credential_claim::Entity::insert_many(credential_claims)
        .exec(database)
        .await?;

    Ok(())
}

// pub async fn get_credential_schema_by_id(
//     database: &DatabaseConnection,
//     id: &str,
// ) -> Result<Option<credential_schema::Model>, DbErr> {
//     credential_schema::Entity::find_by_id(id)
//         .one(database)
//         .await
// }

#[allow(dead_code)]
pub async fn get_credential_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<credential::Model>, DbErr> {
    credential::Entity::find_by_id(id).one(database).await
}

#[allow(dead_code)]
pub async fn get_proof_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<proof::Model>, DbErr> {
    proof::Entity::find_by_id(id).one(database).await
}

// TODO: Will be removed after this task is implemented https://procivis.atlassian.net/browse/ONE-1133
#[allow(dead_code)]
pub async fn get_proof_object_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Proof, DbErr> {
    proof::Entity::find_by_id(id)
        .one(database)
        .await?
        .unwrap()
        .try_into()
        .map_err(|e: DataLayerError| DbErr::RecordNotFound(e.to_string()))
}

pub async fn insert_proof_request_to_database(
    database: &DatabaseConnection,
    verifier_did_id: DidId,
    holder_did_id: Option<DidId>,
    proof_schema_id: &str,
    interaction_id: Option<String>,
) -> Result<String, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        transport: Set("PROCIVIS_TEMPORARY".to_string()),
        verifier_did_id: Set(Some(verifier_did_id)),
        holder_did_id: Set(holder_did_id),
        proof_schema_id: Set(Some(proof_schema_id.to_string())),
        interaction_id: Set(interaction_id),
    }
    .insert(database)
    .await?;
    Ok(proof.id)
}

pub async fn insert_proof_state_to_database(
    database: &DatabaseConnection,
    proof_id: &str,
    state: ProofRequestState,
) -> Result<(), DbErr> {
    proof_state::ActiveModel {
        proof_id: Set(proof_id.to_owned()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        state: Set(state),
    }
    .insert(database)
    .await?;
    Ok(())
}

#[allow(clippy::ptr_arg, dead_code, clippy::too_many_arguments)]
pub async fn insert_proof_request_to_database_with_claims(
    database: &DatabaseConnection,
    verifier_did_id: DidId,
    holder_did_id: Option<DidId>,
    proof_schema_id: Option<String>,
    state: ProofStateEnum,
    transport: &str,
    claims: &Vec<(Uuid, Uuid, String)>,
    interaction_id: Option<String>,
) -> Result<String, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        transport: Set(transport.to_owned()),
        verifier_did_id: Set(Some(verifier_did_id)),
        holder_did_id: Set(holder_did_id),
        proof_schema_id: Set(proof_schema_id),
        interaction_id: Set(interaction_id),
    }
    .insert(database)
    .await?;

    proof_state::ActiveModel {
        proof_id: Set(proof.id.to_owned()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        state: Set(state.into()),
    }
    .insert(database)
    .await?;

    if !claims.is_empty() {
        let claims_to_insert: Vec<claim::ActiveModel> = claims
            .iter()
            .map(|claim| claim::ActiveModel {
                id: Set(claim.0.to_string()),
                claim_schema_id: Set(claim.1.to_string()),
                value: Set(claim.2.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
            })
            .collect();
        claim::Entity::insert_many(claims_to_insert)
            .exec(database)
            .await?;

        let claim_relations: Vec<proof_claim::ActiveModel> = claims
            .iter()
            .map(|claim| proof_claim::ActiveModel {
                claim_id: Set(claim.0.to_string()),
                proof_id: Set(proof.id.clone()),
            })
            .collect();
        proof_claim::Entity::insert_many(claim_relations)
            .exec(database)
            .await?;
    }

    Ok(proof.id)
}

pub async fn insert_proof_schema_with_claims_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    claims: &Vec<(Uuid, &str, bool, u32, &str)>,
    organisation_id: &str,
    name: &str,
) -> Result<String, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(name.to_owned()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id.to_owned()),

        deleted_at: Set(deleted_at),
    }
    .insert(database)
    .await?;

    for (id, _key, required, order, _) in claims {
        proof_schema_claim_schema::ActiveModel {
            claim_schema_id: Set(id.to_string()),
            proof_schema_id: Set(schema.id.clone()),
            required: Set(*required),
            order: Set(*order),
        }
        .insert(database)
        .await?;
    }

    Ok(schema.id)
}

pub async fn insert_proof_schema_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    organisation_id: &str,
    name: &str,
) -> Result<String, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(name.to_owned()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id.to_owned()),

        deleted_at: Set(deleted_at),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub async fn insert_organisation_to_database(
    database: &DatabaseConnection,
    id: Option<Uuid>,
) -> Result<String, DbErr> {
    let organisation = organisation::ActiveModel {
        id: Set(id.unwrap_or_else(Uuid::new_v4).to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
    }
    .insert(database)
    .await?;
    Ok(organisation.id)
}

pub async fn insert_key_to_database(
    database: &DatabaseConnection,
    organisation_id: &str,
) -> Result<String, DbErr> {
    let key = key::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set("test_key".to_string()),
        public_key: Set(vec![]),
        private_key: Set("private".to_string().bytes().collect()),
        storage_type: Set("INTERNAL".to_string()),
        key_type: Set("ED25519".to_string()),
        organisation_id: Set(organisation_id.to_string()),
    }
    .insert(database)
    .await?;
    Ok(key.id)
}

pub async fn get_proof_schema_with_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<proof_schema::Model>, DbErr> {
    proof_schema::Entity::find_by_id(id).one(database).await
}

pub async fn setup_test_data_layer_and_connection_with_custom_url(database_url: &str) -> DataLayer {
    let db_conn = db_conn(database_url).await;
    DataLayer::build(db_conn).await
}

pub async fn insert_did(
    database: &DatabaseConnection,
    name: &str,
    did: DidValue,
    organisation_id: &str,
) -> Result<DidId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let did = did::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        did: Set(did),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set(name.to_owned()),
        type_field: Set(did::DidType::Local),
        method: Set("KEY".to_string()),
        organisation_id: Set(organisation_id.to_owned()),
    }
    .insert(database)
    .await?;

    Ok(did.id)
}

pub async fn insert_key_did(
    database: &DatabaseConnection,
    did_id: &str,
    key_id: &str,
) -> Result<(), DbErr> {
    key_did::ActiveModel {
        did_id: Set(did_id.to_string()),
        key_id: Set(key_id.to_string()),
        role: Set(key_did::KeyRole::Authentication),
    }
    .insert(database)
    .await?;

    Ok(())
}

pub async fn insert_interaction(
    database: &DatabaseConnection,
    host: &str,
    data: &[u8],
) -> Result<String, DbErr> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        host: Set(Some(host.to_owned())),
        data: Set(Some(data.to_owned())),
    }
    .insert(database)
    .await?;

    Ok(interaction.id)
}

// TODO: Will be removed after this task is implemented https://procivis.atlassian.net/browse/ONE-1133
pub async fn get_all_claims(database: &DatabaseConnection) -> Result<Vec<Claim>, DbErr> {
    let claims = claim::Entity::find().all(database).await?;
    Ok(claims
        .into_iter()
        .filter_map(|claim_model| claim_model.try_into().ok())
        .collect())
}

pub async fn get_interaction(
    database: &DatabaseConnection,
    id: &InteractionId,
) -> Result<interaction::Model, DbErr> {
    interaction::Entity::find_by_id(id.to_string())
        .one(database)
        .await?
        .ok_or(DbErr::RecordNotFound(String::default()))
}

// We will bring it back with service unit tests
#[allow(dead_code)]
pub fn get_datatypes() -> HashMap<String, DatatypeEntity> {
    HashMap::from([
        (
            "STRING".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::String,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        ),
        (
            "NUMBER".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Number,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        ),
        (
            "DATE".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Date,
                disabled: None,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        ),
    ])
}

pub async fn setup_test_data_layer_and_connection() -> DataLayer {
    setup_test_data_layer_and_connection_with_custom_url("sqlite::memory:").await
}

// We will bring it back with service unit tests
#[allow(dead_code)]
pub fn get_exchange() -> HashMap<String, ExchangeEntity> {
    HashMap::from([(
        "PROCIVIS_TEMPORARY".to_string(),
        serde_yaml::from_str(
            r#"display: "exchange.procivis"
type: "PROCIVIS_TEMPORARY"
order: 0 # optional to force ordering
params: null"#,
        )
        .unwrap(),
    )])
}

// We will bring it back with service unit tests
#[allow(dead_code)]
pub fn get_did_methods() -> HashMap<String, DidEntity> {
    HashMap::from([(
        "KEY".to_string(),
        serde_yaml::from_str(
            r#"display: "did.key"
type: "KEY"
order: 1
params: null"#,
        )
        .unwrap(),
    )])
}

// We will bring it back with service unit tests
#[allow(dead_code)]
pub fn get_formats() -> HashMap<String, FormatEntity> {
    HashMap::from([(
        "JWT".to_string(),
        serde_yaml::from_str(
            r#"display: "format.jwt"
type: "JWT"
order: 0
params: null"#,
        )
        .unwrap(),
    )])
}

// We will bring it back with service unit tests
#[allow(dead_code)]
pub fn get_revocation_methods() -> HashMap<String, RevocationEntity> {
    HashMap::from([
        (
            "NONE".to_string(),
            serde_yaml::from_str(
                r#"display: "revocation.none"
type: "NONE"
order: 1
params: null"#,
            )
            .unwrap(),
        ),
        (
            "STATUSLIST2021".to_string(),
            serde_yaml::from_str(
                r#"display: "revocation.statuslist2021"
type: "STATUSLIST2021"
order: 10
params: null"#,
            )
            .unwrap(),
        ),
    ])
}

pub fn are_datetimes_within_minute(d1: OffsetDateTime, d2: OffsetDateTime) -> bool {
    (d2 - d1).abs() < Duration::minutes(1)
}

#[test]
fn test_are_datetimes_within_minute() {
    let d1 = get_dummy_date();

    assert!(are_datetimes_within_minute(d1, d1 + Duration::seconds(10)));
    assert!(are_datetimes_within_minute(d1, d1 + Duration::seconds(30)));
    assert!(!are_datetimes_within_minute(
        d1,
        d1 + Duration::seconds(120)
    ));

    assert!(!are_datetimes_within_minute(
        d1 + Duration::seconds(120),
        d1
    ));
}
