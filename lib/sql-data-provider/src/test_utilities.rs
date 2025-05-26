use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use one_core::model::credential::{Credential, CredentialStateEnum};
use one_core::model::did::Did;
use one_core::model::interaction::InteractionId;
use one_core::model::organisation::Organisation;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::{
    ClaimId, ClaimSchemaId, CredentialId, CredentialSchemaId, DidId, DidValue, EntityId, HistoryId,
    IdentifierId, KeyId, OrganisationId, ProofId, ProofSchemaId,
};
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::entity::credential_schema::{CredentialSchemaType, LayoutType, WalletStorageType};
use crate::entity::did::DidType;
use crate::entity::history::{self, HistoryAction, HistoryEntityType};
use crate::entity::key_did::KeyRole;
use crate::entity::proof::{ProofRequestState, ProofRole};
use crate::entity::{
    claim, claim_schema, credential, credential_schema, credential_schema_claim_schema, did,
    identifier, interaction, key, key_did, organisation, proof, proof_claim,
    proof_input_claim_schema, proof_input_schema, proof_schema,
};
use crate::{DataLayer, db_conn};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 +1)
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_credential(
    db: &DatabaseConnection,
    credential_schema_id: &CredentialSchemaId,
    state: CredentialStateEnum,
    protocol: &str,
    issuer_identifier_id: IdentifierId,
    deleted_at: Option<OffsetDateTime>,
    suspend_end_date: Option<OffsetDateTime>,
) -> Result<Credential, DbErr> {
    let now = OffsetDateTime::now_utc();

    let credential = credential::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        credential_schema_id: Set(*credential_schema_id),
        created_date: Set(now),
        last_modified: Set(now),
        issuance_date: Set(now),
        redirect_uri: Set(None),
        deleted_at: Set(deleted_at),
        exchange: Set(protocol.to_owned()),
        credential: Set(vec![0, 0, 0, 0]),
        role: Set(credential::CredentialRole::Issuer),
        issuer_identifier_id: Set(Some(issuer_identifier_id)),
        holder_identifier_id: Set(None),
        interaction_id: Set(None),
        revocation_list_id: Set(None),
        key_id: Set(None),
        state: Set(state.into()),
        suspend_end_date: Set(suspend_end_date),
    }
    .insert(db)
    .await?;

    Ok(credential.into())
}

pub async fn update_credential_state(
    database: &DatabaseConnection,
    credential_id: CredentialId,
    state: CredentialStateEnum,
    suspend_end_date: Option<OffsetDateTime>,
    last_modified: OffsetDateTime,
) -> Result<(), DbErr> {
    credential::ActiveModel {
        id: Set(credential_id),
        state: Set(state.into()),
        last_modified: Set(last_modified),
        suspend_end_date: Set(suspend_end_date),
        ..Default::default()
    }
    .update(database)
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
) -> Result<CredentialSchemaId, DbErr> {
    let new_id: CredentialSchemaId = Uuid::new_v4().into();
    let schema = credential_schema::ActiveModel {
        id: Set(new_id.to_owned()),
        imported_source_url: Set("CORE_URL".to_string()),
        created_date: Set(get_dummy_date()),
        external_schema: Set(false),
        last_modified: Set(get_dummy_date()),
        format: Set(format.to_owned()),
        name: Set(name.to_owned()),
        revocation_method: Set(revocation_method.to_owned()),
        organisation_id: Set(organisation_id),
        wallet_storage_type: Set(Some(WalletStorageType::Software)),
        deleted_at: Set(deleted_at),
        layout_type: Set(LayoutType::Card),
        layout_properties: Set(None),
        schema_type: Set(CredentialSchemaType::ProcivisOneSchema2024),
        schema_id: Set(new_id.to_string()),
        allow_suspension: Set(true),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub async fn insert_many_claims_to_database(
    database: &DatabaseConnection,
    claims: &[(ClaimId, ClaimSchemaId, CredentialId, Vec<u8>, String)],
) -> Result<(), DbErr> {
    let models =
        claims.iter().map(
            |(id, claim_schema_id, credential_id, value, path)| claim::ActiveModel {
                id: Set(*id),
                claim_schema_id: Set(*claim_schema_id),
                credential_id: Set(*credential_id),
                value: Set(value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
                path: Set(path.to_owned()),
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
            array: Set(claim_schema.array),
        }
        .insert(database)
        .await?;

        credential_schema_claim_schema::ActiveModel {
            claim_schema_id: Set(claim_schema.id),
            credential_schema_id: Set(claim_input.credential_schema_id.to_string()),
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
    id: &ProofId,
) -> Result<Option<proof::Model>, DbErr> {
    proof::Entity::find_by_id(id).one(database).await
}

pub async fn insert_proof_request_to_database(
    database: &DatabaseConnection,
    verifier_identifier_id: IdentifierId,
    holder_identifier_id: Option<IdentifierId>,
    proof_schema_id: &ProofSchemaId,
    verifier_key_id: KeyId,
    interaction_id: Option<String>,
) -> Result<ProofId, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        issuance_date: Set(get_dummy_date()),
        exchange: Set("OPENID4VP_DRAFT20".to_string()),
        transport: Set("HTTP".to_string()),
        redirect_uri: Set(None),
        state: Set(ProofRequestState::Created),
        role: Set(ProofRole::Verifier),
        requested_date: Set(None),
        completed_date: Set(None),
        verifier_identifier_id: Set(Some(verifier_identifier_id)),
        holder_identifier_id: Set(holder_identifier_id),
        proof_schema_id: Set(Some(*proof_schema_id)),
        verifier_key_id: Set(Some(verifier_key_id)),
        verifier_certificate_id: Set(None),
        interaction_id: Set(interaction_id),
    }
    .insert(database)
    .await?;
    Ok(proof.id)
}

pub struct ClaimInsertInfo<'a> {
    pub id: ClaimSchemaId,
    pub key: &'a str,
    pub required: bool,
    pub order: u32,
    pub datatype: &'a str,
    pub array: bool,
}

pub struct ProofInput<'a> {
    pub credential_schema_id: CredentialSchemaId,
    pub claims: &'a Vec<ClaimInsertInfo<'a>>,
}

pub async fn insert_proof_schema_with_claims_to_database(
    database: &DatabaseConnection,
    deleted_at: Option<OffsetDateTime>,
    proof_inputs: Vec<&ProofInput<'_>>,
    organisation_id: OrganisationId,
    name: &str,
) -> Result<ProofSchemaId, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        imported_source_url: Set(Some("CORE_URL".to_string())),
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
            credential_schema: Set(input.credential_schema_id.to_string()),
            proof_schema: Set(schema.id),
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
) -> Result<ProofSchemaId, DbErr> {
    let schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        imported_source_url: Set(Some("CORE_URL".to_string())),
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
    proof_claims: &[(ProofId, ClaimId)],
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
    name: Option<String>,
) -> Result<OrganisationId, DbErr> {
    let id = id.unwrap_or(Uuid::new_v4().into());
    let organisation = organisation::ActiveModel {
        id: Set(id),
        name: Set(name.unwrap_or(id.to_string())),
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
    id: &ProofSchemaId,
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
        organisation_id: Set(Some(organisation_id)),
        deactivated: Set(deactivated.into().unwrap_or_default()),
        deleted_at: NotSet,
        log: NotSet,
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

pub async fn insert_identifier(
    database: &DatabaseConnection,
    name: &str,
    identifier_id: impl Into<IdentifierId>,
    did_id: Option<DidId>,
    organisation_id: OrganisationId,
    remote: impl Into<bool>,
) -> Result<IdentifierId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let identifier = identifier::ActiveModel {
        id: Set(identifier_id.into()),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set(name.to_owned()),
        organisation_id: Set(Some(organisation_id)),
        deleted_at: NotSet,
        r#type: Set(identifier::IdentifierType::Did),
        is_remote: Set(remote.into()),
        state: Set(identifier::IdentifierState::Active),
        did_id: Set(did_id),
        key_id: NotSet,
    }
    .insert(database)
    .await?;

    Ok(identifier.id)
}

pub async fn insert_interaction(
    database: &DatabaseConnection,
    host: &str,
    data: &[u8],
    organisation_id: OrganisationId,
) -> Result<String, DbErr> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        host: Set(Some(host.to_owned())),
        data: Set(Some(data.to_owned())),
        organisation_id: Set(organisation_id),
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
    name: String,
) -> Result<HistoryId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let model = history::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(now),
        action: Set(action),
        name: Set(name),
        entity_id: Set(Some(entity_id)),
        entity_type: Set(entity_type),
        metadata: Set(None),
        organisation_id: Set(organisation_id),
        target: Set(None),
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

pub fn dummy_organisation(id: Option<OrganisationId>) -> Organisation {
    let id = id.unwrap_or(Uuid::new_v4().into());
    Organisation {
        name: format!("{id}"),
        id,
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
    }
}

pub fn dummy_did() -> Did {
    Did {
        id: Uuid::new_v4().into(),
        created_date: OffsetDateTime::now_utc(),
        last_modified: OffsetDateTime::now_utc(),
        name: "John".to_string(),
        did: "did:example:123".parse().unwrap(),
        did_type: one_core::model::did::DidType::Local,
        did_method: "INTERNAL".to_string(),
        keys: None,
        organisation: Some(dummy_organisation(None)),
        deactivated: false,
        log: None,
    }
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
