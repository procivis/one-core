use one_core::model::credential::{CredentialState, CredentialStateEnum};
use one_core::model::interaction::InteractionId;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::{DidId, DidValue, EntityId, HistoryId, OrganisationId};
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    db_conn,
    entity::{
        claim, claim_schema, credential, credential_schema, credential_schema_claim_schema,
        credential_state, did,
        did::DidType,
        history::{self, HistoryAction, HistoryEntityType},
        interaction, key, key_did,
        key_did::KeyRole,
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
    deleted_at: Option<OffsetDateTime>,
) -> Result<String, DbErr> {
    let now = OffsetDateTime::now_utc();

    let credential = credential::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        credential_schema_id: Set(credential_schema_id.to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        issuance_date: Set(now),
        redirect_uri: Set(None),
        deleted_at: Set(deleted_at),
        transport: Set(protocol.to_owned()),
        credential: Set(vec![0, 0, 0, 0]),
        role: Set(credential::CredentialRole::Issuer),
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

pub async fn insert_credential_state_to_database(
    database: &DatabaseConnection,
    credential_id: &str,
    state: CredentialState,
) -> Result<(), DbErr> {
    credential_state::ActiveModel {
        credential_id: Set(credential_id.to_owned()),
        created_date: Set(state.created_date),
        state: Set(state.state.into()),
    }
    .insert(database)
    .await?;
    Ok(())
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

pub async fn insert_many_claims_to_database(
    database: &DatabaseConnection,
    claims: &[(Uuid, Uuid, &str, Vec<u8>)],
) -> Result<(), DbErr> {
    let models =
        claims.iter().map(
            |(id, claim_schema_id, credential_id, value)| claim::ActiveModel {
                id: Set(id.to_string()),
                claim_schema_id: Set(claim_schema_id.to_string()),
                credential_id: Set(credential_id.to_string()),
                value: Set(value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
            },
        );

    claim::Entity::insert_many(models).exec(database).await?;
    Ok(())
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

pub async fn get_proof_by_id(
    database: &DatabaseConnection,
    id: &str,
) -> Result<Option<proof::Model>, DbErr> {
    proof::Entity::find_by_id(id).one(database).await
}

pub async fn insert_proof_request_to_database(
    database: &DatabaseConnection,
    verifier_did_id: DidId,
    holder_did_id: Option<DidId>,
    proof_schema_id: &str,
    verifier_key_id: String,
    interaction_id: Option<String>,
) -> Result<String, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        transport: Set("PROCIVIS_TEMPORARY".to_string()),
        redirect_uri: Set(None),
        verifier_did_id: Set(Some(verifier_did_id)),
        holder_did_id: Set(holder_did_id),
        proof_schema_id: Set(Some(proof_schema_id.to_string())),
        verifier_key_id: Set(Some(verifier_key_id)),
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

pub async fn insert_many_proof_claim_to_database(
    database: &DatabaseConnection,
    proof_claims: &[(Uuid, Uuid)],
) -> Result<(), DbErr> {
    let models = proof_claims
        .iter()
        .map(|(proof_id, claim_id)| proof_claim::ActiveModel {
            claim_id: Set(claim_id.to_string()),
            proof_id: Set(proof_id.to_string()),
        });

    proof_claim::Entity::insert_many(models)
        .exec(database)
        .await?;

    Ok(())
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
    key_type: String,
    public_key: Vec<u8>,
    key_reference: Vec<u8>,
    did_id: Option<DidId>,
    organisation_id: &str,
) -> Result<String, DbErr> {
    let id = did_id
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let key = key::ActiveModel {
        id: Set(id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set("test_key".to_string()),
        public_key: Set(public_key),
        key_reference: Set(key_reference),
        storage_type: Set("INTERNAL".to_string()),
        key_type: Set(key_type),
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
    let db_conn = db_conn(database_url).await.unwrap();
    DataLayer::build(db_conn)
}

pub async fn insert_did_key(
    database: &DatabaseConnection,
    name: &str,
    did_id: impl Into<DidId>,
    did: DidValue,
    method: &str,
    organisation_id: &str,
) -> Result<DidId, DbErr> {
    insert_did(
        database,
        name,
        did_id.into(),
        did,
        organisation_id,
        method,
        DidType::Local,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_did(
    database: &DatabaseConnection,
    name: &str,
    did_id: DidId,
    did: DidValue,
    organisation_id: &str,
    method: impl Into<String>,
    did_type: DidType,
    deactivated: impl Into<Option<bool>>,
) -> Result<DidId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let did = did::ActiveModel {
        id: Set(did_id),
        did: Set(did),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set(name.to_owned()),
        type_field: Set(did_type),
        method: Set(method.into()),
        organisation_id: Set(organisation_id.to_owned()),
        deactivated: Set(deactivated.into().unwrap_or_default()),
    }
    .insert(database)
    .await?;

    Ok(did.id)
}

pub async fn insert_key_did(
    database: &DatabaseConnection,
    did_id: &str,
    key_id: &str,
    role: KeyRole,
) -> Result<(), DbErr> {
    key_did::ActiveModel {
        did_id: Set(did_id.to_string()),
        key_id: Set(key_id.to_string()),
        role: Set(role),
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

pub async fn get_interaction(
    database: &DatabaseConnection,
    id: &InteractionId,
) -> Result<interaction::Model, DbErr> {
    interaction::Entity::find_by_id(id.to_string())
        .one(database)
        .await?
        .ok_or(DbErr::RecordNotFound(String::default()))
}

pub async fn setup_test_data_layer_and_connection() -> DataLayer {
    setup_test_data_layer_and_connection_with_custom_url("sqlite::memory:").await
}

pub fn are_datetimes_within_minute(d1: OffsetDateTime, d2: OffsetDateTime) -> bool {
    (d2 - d1).abs() < Duration::minutes(1)
}

pub async fn insert_history(
    database: &DatabaseConnection,
    action: HistoryAction,
    entity_id: EntityId,
    entity_type: HistoryEntityType,
    organisation_id: OrganisationId,
) -> Result<HistoryId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let model = history::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(now),
        action: Set(action),
        entity_id: Set(entity_id),
        entity_type: Set(entity_type),
        organisation_id: Set(organisation_id),
    }
    .insert(database)
    .await?;

    Ok(model.id)
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
