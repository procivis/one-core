use shared_types::{ClaimId, ClaimSchemaId};
use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use one_core::model::credential::{CredentialState, CredentialStateEnum};
use one_core::model::interaction::InteractionId;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::{CredentialId, DidId, DidValue, EntityId, HistoryId, KeyId, OrganisationId};
use time::{macros::datetime, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::entity::credential_schema::{CredentialSchemaType, LayoutType};
use crate::entity::{proof_input_claim_schema, proof_input_schema};
use crate::{
    db_conn,
    entity::{
        claim, claim_schema, credential, credential_schema, credential_schema_claim_schema,
        credential_state, did,
        did::DidType,
        history::{self, HistoryAction, HistoryEntityType},
        interaction, key, key_did,
        key_did::KeyRole,
        organisation, proof, proof_claim, proof_schema,
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
) -> Result<CredentialId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let credential = credential::ActiveModel {
        id: Set(Uuid::new_v4().into()),
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
        credential_id: Set(credential.id),
        created_date: Set(now),
        state: Set(state.into()),
        suspend_end_date: Set(None),
    }
    .insert(db)
    .await?;

    Ok(credential.id)
}

pub async fn insert_credential_state_to_database(
    database: &DatabaseConnection,
    credential_id: CredentialId,
    state: CredentialState,
) -> Result<(), DbErr> {
    credential_state::ActiveModel {
        credential_id: Set(credential_id),
        created_date: Set(state.created_date),
        state: Set(state.state.into()),
        suspend_end_date: Set(state.suspend_end_date),
    }
    .insert(database)
    .await?;
    Ok(())
}

pub async fn insert_credential_schema_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    organisation_id: OrganisationId,
    name: &str,
    format: &str,
    revocation_method: &str,
) -> Result<String, DbErr> {
    let new_id = Uuid::new_v4().to_string();
    let schema = credential_schema::ActiveModel {
        id: Set(new_id.to_owned()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        format: Set(format.to_owned()),
        name: Set(name.to_owned()),
        revocation_method: Set(revocation_method.to_owned()),
        organisation_id: Set(organisation_id),
        wallet_storage_type: Set(None),
        deleted_at: Set(deleted_at),
        layout_type: Set(LayoutType::Card),
        layout_properties: Set(None),
        schema_type: Set(CredentialSchemaType::ProcivisOneSchema2024),
        schema_id: Set(new_id),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub async fn insert_many_claims_to_database(
    database: &DatabaseConnection,
    claims: &[(ClaimId, ClaimSchemaId, CredentialId, Vec<u8>)],
) -> Result<(), DbErr> {
    let models =
        claims.iter().map(
            |(id, claim_schema_id, credential_id, value)| claim::ActiveModel {
                id: Set(*id),
                claim_schema_id: Set(*claim_schema_id),
                credential_id: Set(*credential_id),
                value: Set(value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
            },
        );

    claim::Entity::insert_many(models).exec(database).await?;
    Ok(())
}

#[allow(clippy::ptr_arg)]
pub async fn insert_many_claims_schema_to_database<'a>(
    database: &DatabaseConnection,
    claim_input: &'a ProofInput<'a>,
) -> Result<(), DbErr> {
    for claim_schema in claim_input.claims {
        claim_schema::ActiveModel {
            id: Set(claim_schema.id),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            key: Set(claim_schema.key.to_string()),
            datatype: Set(claim_schema.datatype.to_string()),
        }
        .insert(database)
        .await?;

        credential_schema_claim_schema::ActiveModel {
            claim_schema_id: Set(claim_schema.id),
            credential_schema_id: Set(claim_input.credential_schema_id.to_owned()),
            required: Set(claim_schema.required),
            order: Set(claim_schema.order),
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
    verifier_key_id: KeyId,
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

pub struct ClaimInsertInfo<'a> {
    pub id: ClaimSchemaId,
    pub key: &'a str,
    pub required: bool,
    pub order: u32,
    pub datatype: &'a str,
}

pub struct ProofInput<'a> {
    pub credential_schema_id: String,
    pub claims: &'a Vec<ClaimInsertInfo<'a>>,
}

pub async fn insert_proof_schema_with_claims_to_database<'a>(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    proof_inputs: Vec<&ProofInput<'a>>,
    organisation_id: OrganisationId,
    name: &str,
) -> Result<String, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(name.to_owned()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(deleted_at),
    }
    .insert(database)
    .await?;

    for (i, input) in proof_inputs.iter().enumerate() {
        let input_id = proof_input_schema::ActiveModel {
            id: NotSet,
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            order: Set(i as _),
            validity_constraint: NotSet,
            credential_schema: Set(input.credential_schema_id.to_owned()),
            proof_schema: Set(schema.id.clone()),
        }
        .insert(database)
        .await?;

        for claim in input.claims {
            proof_input_claim_schema::ActiveModel {
                proof_input_schema_id: Set(input_id.id),
                claim_schema_id: Set(claim.id.to_string()),
                required: Set(claim.required),
                order: Set(claim.order as _),
            }
            .insert(database)
            .await?;
        }
    }

    Ok(schema.id)
}

pub async fn insert_proof_schema_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    organisation_id: OrganisationId,
    name: &str,
) -> Result<String, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(name.to_owned()),
        expire_duration: Set(Default::default()),
        organisation_id: Set(organisation_id),
        deleted_at: Set(deleted_at),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub async fn insert_many_proof_claim_to_database(
    database: &DatabaseConnection,
    proof_claims: &[(Uuid, ClaimId)],
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
    id: Option<OrganisationId>,
) -> Result<OrganisationId, DbErr> {
    let organisation = organisation::ActiveModel {
        id: Set(id.unwrap_or(Uuid::new_v4().into())),
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
    organisation_id: OrganisationId,
) -> Result<KeyId, DbErr> {
    let id = did_id
        .as_ref()
        .map(|id| (*id).into())
        .unwrap_or_else(Uuid::new_v4);

    let key = key::ActiveModel {
        id: Set(id.into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set("test_key".to_string()),
        public_key: Set(public_key),
        key_reference: Set(key_reference),
        storage_type: Set("INTERNAL".to_string()),
        key_type: Set(key_type),
        organisation_id: Set(organisation_id),
        deleted_at: NotSet,
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
    let db_conn = db_conn(database_url, true).await.unwrap();
    DataLayer::build(db_conn, vec![])
}

pub async fn insert_did_key(
    database: &DatabaseConnection,
    name: &str,
    did_id: impl Into<DidId>,
    did: DidValue,
    method: &str,
    organisation_id: OrganisationId,
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
    organisation_id: OrganisationId,
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
        organisation_id: Set(organisation_id),
        deactivated: Set(deactivated.into().unwrap_or_default()),
        deleted_at: NotSet,
    }
    .insert(database)
    .await?;

    Ok(did.id)
}

pub async fn insert_key_did(
    database: &DatabaseConnection,
    did_id: DidId,
    key_id: KeyId,
    role: KeyRole,
) -> Result<(), DbErr> {
    key_did::ActiveModel {
        did_id: Set(did_id),
        key_id: Set(key_id),
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
        entity_id: Set(Some(entity_id)),
        entity_type: Set(entity_type),
        metadata: Set(None),
        organisation_id: Set(organisation_id),
    }
    .insert(database)
    .await?;

    Ok(model.id)
}

pub fn assert_eq_unordered<T: Hash + Eq + Debug, K: Into<T>>(
    left: impl IntoIterator<Item = T>,
    right: impl IntoIterator<Item = K>,
) {
    assert_eq!(
        left.into_iter().collect::<HashSet<_>>(),
        right.into_iter().map(Into::into).collect::<HashSet<_>>(),
    );
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
