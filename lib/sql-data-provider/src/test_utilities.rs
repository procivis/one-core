use migration::{Migrator, MigratorTrait};
use one_core::config::data_structure::{
    DatatypeEntity, DatatypeType, DidEntity, ExchangeEntity, FormatEntity, RevocationEntity,
    TranslatableString,
};
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use std::collections::HashMap;
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    entity::{
        claim, claim_schema, credential, credential_claim, credential_schema,
        credential_schema_claim_schema, credential_state, did, organisation, proof, proof_claim,
        proof_schema, proof_schema_claim_schema,
        proof_state::{self, ProofRequestState},
    },
    DataLayer, OldProvider,
};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

pub async fn insert_credential(
    db: &DatabaseConnection,
    credential_schema_id: &str,
    did_id: &str,
) -> Result<String, DbErr> {
    let now = OffsetDateTime::now_utc();

    let credential = credential::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        credential_schema_id: Set(credential_schema_id.to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        issuance_date: Set(now),
        deleted_at: Set(None),
        transport: Set("PROCIVIS_TEMPORARY".to_string()),
        credential: Set(vec![0, 0, 0, 0]),
        issuer_did_id: Set(did_id.to_string()),
        receiver_did_id: Set(None),
    }
    .insert(db)
    .await?;

    credential_state::ActiveModel {
        credential_id: Set(credential.id.to_owned()),
        created_date: Set(now),
        state: Set(credential_state::CredentialState::Created),
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
) -> Result<String, DbErr> {
    let schema = credential_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        format: Set(Default::default()),
        name: Set(name.to_owned()),
        revocation_method: Set(Default::default()),
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
    claims: &Vec<(Uuid, bool, u32, &str)>,
) -> Result<(), DbErr> {
    for (id, required, order, datatype) in claims {
        claim_schema::ActiveModel {
            id: Set(id.to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set("TestKey".to_string()),
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
pub async fn insert_many_credential_claims_to_database(
    database: &DatabaseConnection,
    credential_id: &str,
    claims: &Vec<(Uuid, String)>,
) -> Result<(), DbErr> {
    let claims_to_insert = claims
        .iter()
        .map(|(claim_schema_id, value)| claim::ActiveModel {
            // Just for tests id of a claim will be the same as id for a schema it instantiates
            id: Set(claim_schema_id.to_string()),
            claim_schema_id: Set(claim_schema_id.to_string()),
            value: Set(value.to_owned()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
        });

    let credential_claims =
        claims
            .iter()
            .map(|(claim_schema_id, ..)| credential_claim::ActiveModel {
                claim_id: Set(claim_schema_id.to_string()),
                credential_id: Set(credential_id.to_owned()),
            });

    claim::Entity::insert_many(claims_to_insert)
        .exec(database)
        .await?;

    credential_claim::Entity::insert_many(credential_claims)
        .exec(database)
        .await?;

    Ok(())
}

pub async fn get_credential_schema_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<credential_schema::Model>, DbErr> {
    credential_schema::Entity::find_by_id(id)
        .one(database)
        .await
}

pub async fn get_credential_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<credential::Model>, DbErr> {
    credential::Entity::find_by_id(id).one(database).await
}

pub async fn get_proof_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<proof::Model>, DbErr> {
    proof::Entity::find_by_id(id).one(database).await
}

pub async fn insert_proof_request_to_database(
    database: &DatabaseConnection,
    verifier_did_id: &str,
    receiver_did_id: Option<String>,
    proof_schema_id: &str,
) -> Result<String, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        verifier_did_id: Set(verifier_did_id.to_string()),
        receiver_did_id: Set(receiver_did_id),
        proof_schema_id: Set(proof_schema_id.to_string()),
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

#[allow(clippy::ptr_arg)]
pub async fn insert_proof_request_to_database_with_claims(
    database: &DatabaseConnection,
    verifier_did_id: &str,
    receiver_did_id: Option<String>,
    proof_schema_id: &str,
    state: ProofRequestState,
    claims: &Vec<(Uuid, Uuid, String)>,
) -> Result<String, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        verifier_did_id: Set(verifier_did_id.to_string()),
        receiver_did_id: Set(receiver_did_id),
        proof_schema_id: Set(proof_schema_id.to_string()),
    }
    .insert(database)
    .await?;

    proof_state::ActiveModel {
        proof_id: Set(proof.id.to_owned()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        state: Set(state),
    }
    .insert(database)
    .await?;

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

    Ok(proof.id)
}

pub async fn insert_proof_schema_with_claims_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    claims: &Vec<(Uuid, bool, u32, &str)>,
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

    for (id, required, order, _) in claims {
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

pub async fn get_proof_schema_with_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<proof_schema::Model>, DbErr> {
    proof_schema::Entity::find_by_id(id).one(database).await
}

pub(crate) async fn setup_test_data_provider_and_connection_with_custom_url(
    database_url: &str,
) -> Result<OldProvider, DbErr> {
    let db = sea_orm::Database::connect(database_url)
        .await
        .expect("Database Connected");

    Migrator::up(&db, None).await.unwrap();

    Ok(OldProvider { db })
}

pub async fn setup_test_data_layer_and_connection_with_custom_url(database_url: &str) -> DataLayer {
    DataLayer::create(database_url).await
}

pub async fn insert_did(
    database: &DatabaseConnection,
    name: &str,
    did: &str,
    organisation_id: &str,
) -> Result<String, DbErr> {
    let now = OffsetDateTime::now_utc();

    let did = did::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        did: Set(did.to_owned()),
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

pub fn get_datatypes() -> HashMap<String, DatatypeEntity> {
    HashMap::from([
        (
            "STRING".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::String,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        ),
        (
            "NUMBER".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Number,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        ),
        (
            "DATE".to_string(),
            DatatypeEntity {
                r#type: DatatypeType::Date,
                display: TranslatableString::Key("Display".to_string()),
                order: None,
                params: None,
            },
        ),
    ])
}

pub(crate) async fn setup_test_data_provider_and_connection() -> Result<OldProvider, DbErr> {
    setup_test_data_provider_and_connection_with_custom_url("sqlite::memory:").await
}

pub async fn setup_test_data_layer_and_connection() -> DataLayer {
    setup_test_data_layer_and_connection_with_custom_url("sqlite::memory:").await
}

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
