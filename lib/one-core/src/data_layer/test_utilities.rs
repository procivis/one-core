use migration::{Migrator, MigratorTrait};
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::data_layer::{
    entities::{
        claim_schema, credential, credential::Transport, credential_schema,
        credential_schema_claim_schema, credential_state, did, organisation, proof_schema,
        proof_schema_claim_schema,
    },
    DataLayer,
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
        transport: Set(Transport::ProcivisTemporary),
        credential: Set(vec![0, 0, 0, 0]),
        did_id: Set(Some(did_id.to_string())),
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
    claims: &Vec<(Uuid, bool, u32, claim_schema::Datatype)>,
) -> Result<(), DbErr> {
    for (id, required, order, datatype) in claims {
        claim_schema::ActiveModel {
            id: Set(id.to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set("TestKey".to_string()),
            datatype: Set(datatype.to_owned()),
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

pub async fn get_credential_schema_with_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<credential_schema::Model>, DbErr> {
    credential_schema::Entity::find_by_id(id)
        .one(database)
        .await
}

pub async fn insert_proof_schema_with_claims_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    claims: &Vec<(Uuid, bool, u32, claim_schema::Datatype)>,
    organisation_id: &str,
) -> Result<String, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(Default::default()),
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

pub async fn setup_test_data_layer_and_connection_with_custom_url(
    database_url: &str,
) -> Result<DataLayer, DbErr> {
    let db = sea_orm::Database::connect(database_url)
        .await
        .expect("Database Connected");

    Migrator::up(&db, None).await.unwrap();

    Ok(DataLayer { db })
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
        method: Set(did::DidMethod::Key),
        organisation_id: Set(organisation_id.to_owned()),
    }
    .insert(database)
    .await?;

    Ok(did.id)
}

pub async fn setup_test_data_layer_and_connection() -> Result<DataLayer, DbErr> {
    setup_test_data_layer_and_connection_with_custom_url("sqlite::memory:").await
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
