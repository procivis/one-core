#![expect(clippy::unwrap_used)]

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

use one_core::model::credential::{Credential, CredentialStateEnum};
use one_core::model::organisation::Organisation;
use one_core::model::wallet_unit::WalletProviderType;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::{
    BlobId, CertificateId, ClaimId, ClaimSchemaId, CredentialId, CredentialSchemaId, DidId,
    DidValue, EntityId, HistoryId, IdentifierId, InteractionId, KeyId, NonceId, OrganisationId,
    ProofId, ProofSchemaId, RevocationListId, WalletUnitAttestedKeyId, WalletUnitId,
};
use similar_asserts::assert_eq;
use standardized_types::jwk::PublicJwk;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::entity::blob::BlobType;
use crate::entity::credential_schema::{KeyStorageSecurity, LayoutType};
use crate::entity::did::DidType;
use crate::entity::history::{self, HistoryAction, HistoryEntityType};
use crate::entity::interaction::InteractionType;
use crate::entity::key_did::KeyRole;
use crate::entity::proof::{ProofRequestState, ProofRole};
use crate::entity::revocation_list::{
    RevocationListFormat, RevocationListPurpose, RevocationListType,
};
use crate::entity::revocation_list_entry::{RevocationListEntryStatus, RevocationListEntryType};
use crate::entity::{
    blob, claim, claim_schema, credential, credential_schema, did, identifier, interaction, key,
    key_did, organisation, proof, proof_claim, proof_input_claim_schema, proof_input_schema,
    proof_schema, revocation_list, revocation_list_entry, wallet_unit, wallet_unit_attested_key,
};
use crate::{DataLayer, db_conn};

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 UTC)
}

#[expect(clippy::too_many_arguments)]
pub async fn insert_credential(
    db: &DatabaseConnection,
    credential_schema_id: &CredentialSchemaId,
    state: CredentialStateEnum,
    protocol: &str,
    issuer_identifier_id: IdentifierId,
    deleted_at: Option<OffsetDateTime>,
    suspend_end_date: Option<OffsetDateTime>,
    credential_blob_id: BlobId,
) -> Result<Credential, DbErr> {
    let now = OffsetDateTime::now_utc();

    blob::ActiveModel {
        id: Set(credential_blob_id),
        created_date: Set(now),
        last_modified: Set(now),
        value: Set(vec![0, 0, 0, 0]),
        r#type: Set(BlobType::Credential),
    }
    .insert(db)
    .await?;

    let credential = credential::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        credential_schema_id: Set(*credential_schema_id),
        created_date: Set(now),
        last_modified: Set(now),
        issuance_date: Set(None),
        redirect_uri: Set(None),
        deleted_at: Set(deleted_at),
        protocol: Set(protocol.to_owned()),
        role: Set(credential::CredentialRole::Issuer),
        issuer_identifier_id: Set(Some(issuer_identifier_id)),
        issuer_certificate_id: Set(None),
        holder_identifier_id: Set(None),
        interaction_id: Set(None),
        key_id: Set(None),
        state: Set(state.into()),
        suspend_end_date: Set(suspend_end_date),
        profile: Set(None),
        credential_blob_id: Set(Some(credential_blob_id)),
        wallet_unit_attestation_blob_id: Set(None),
        wallet_app_attestation_blob_id: Set(None),
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
    key_storage_security: Option<KeyStorageSecurity>,
) -> Result<CredentialSchemaId, DbErr> {
    let new_id: CredentialSchemaId = Uuid::new_v4().into();
    let schema = credential_schema::ActiveModel {
        id: Set(new_id.to_owned()),
        imported_source_url: Set("CORE_URL".to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        format: Set(format.into()),
        name: Set(name.to_owned()),
        revocation_method: Set(revocation_method.to_owned()),
        organisation_id: Set(organisation_id),
        key_storage_security: Set(key_storage_security),
        deleted_at: Set(deleted_at),
        layout_type: Set(LayoutType::Card),
        layout_properties: Set(None),
        schema_id: Set(new_id.to_string()),
        allow_suspension: Set(true),
        requires_app_attestation: Set(key_storage_security.is_some()),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub type ClaimList<'a> = &'a [(
    ClaimId,
    ClaimSchemaId,
    CredentialId,
    Option<Vec<u8>>,
    String,
    bool,
)];
pub async fn insert_many_claims_to_database(
    database: &DatabaseConnection,
    claims: ClaimList<'_>,
) -> Result<(), DbErr> {
    let models = claims.iter().map(
        |(id, claim_schema_id, credential_id, value, path, selectively_disclosable)| {
            claim::ActiveModel {
                id: Set(*id),
                claim_schema_id: Set(*claim_schema_id),
                credential_id: Set(*credential_id),
                value: Set(value.to_owned()),
                created_date: Set(get_dummy_date()),
                last_modified: Set(get_dummy_date()),
                path: Set(path.to_owned()),
                selectively_disclosable: Set(*selectively_disclosable),
            }
        },
    );

    claim::Entity::insert_many(models).exec(database).await?;
    Ok(())
}

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
            metadata: Set(claim_schema.metadata),
            credential_schema_id: Set(claim_input.credential_schema_id),
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
    proof_schema_id: &ProofSchemaId,
    verifier_key_id: KeyId,
    interaction_id: Option<InteractionId>,
    proof_blob_id: Option<BlobId>,
    engagement: Option<String>,
) -> Result<ProofId, DbErr> {
    let proof = proof::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        protocol: Set("OPENID4VP_DRAFT20".to_string()),
        transport: Set("HTTP".to_string()),
        redirect_uri: Set(None),
        state: Set(ProofRequestState::Created),
        role: Set(ProofRole::Verifier),
        requested_date: Set(None),
        completed_date: Set(None),
        verifier_identifier_id: Set(Some(verifier_identifier_id)),
        proof_schema_id: Set(Some(*proof_schema_id)),
        verifier_key_id: Set(Some(verifier_key_id)),
        verifier_certificate_id: Set(None),
        interaction_id: Set(interaction_id),
        profile: Set(None),
        proof_blob_id: Set(proof_blob_id),
        engagement: Set(engagement),
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
    pub metadata: bool,
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
            credential_schema: Set(input.credential_schema_id),
            proof_schema: Set(schema.id),
        }
        .insert(database)
        .await?;

        for claim in input.claims {
            proof_input_claim_schema::ActiveModel {
                proof_input_schema_id: Set(input_id.id),
                claim_schema_id: Set(claim.id),
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
            claim_id: Set(*claim_id),
            proof_id: Set(*proof_id),
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
        deactivated_at: NotSet,
        wallet_provider: NotSet,
        wallet_provider_issuer: NotSet,
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
        key_reference: Set(Some(key_reference)),
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

#[expect(clippy::too_many_arguments)]
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
        reference: Set("1".to_string()),
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
    data: &[u8],
    organisation_id: OrganisationId,
    nonce_id: Option<NonceId>,
    interaction_type: InteractionType,
) -> Result<InteractionId, DbErr> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(now),
        last_modified: Set(now),
        data: Set(Some(data.to_owned())),
        organisation_id: Set(organisation_id),
        nonce_id: Set(nonce_id),
        interaction_type: Set(interaction_type),
        expires_at: Set(None),
    }
    .insert(database)
    .await?;

    Ok(interaction.id)
}

pub async fn get_interaction(
    database: &DatabaseConnection,
    id: &InteractionId,
) -> Result<interaction::Model, DbErr> {
    interaction::Entity::find_by_id(id)
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
        organisation_id: Set(Some(organisation_id)),
        source: Set(history::HistorySource::Core),
        target: Set(None),
        //TODO: pass user
        user: Set(None),
    }
    .insert(database)
    .await?;

    Ok(model.id)
}

pub async fn insert_revocation_list(
    database: &DatabaseConnection,
    purpose: RevocationListPurpose,
    format: RevocationListFormat,
    issuer_identifier_id: IdentifierId,
    r#type: RevocationListType,
    issuer_certificate_id: Option<CertificateId>,
) -> Result<RevocationListId, DbErr> {
    let id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();

    let _model = revocation_list::ActiveModel {
        id: Set(id),
        created_date: Set(now),
        last_modified: Set(now),
        formatted_list: Set(vec![]),
        purpose: Set(purpose),
        format: Set(format),
        r#type: Set(r#type),
        issuer_identifier_id: Set(issuer_identifier_id),
        issuer_certificate_id: Set(issuer_certificate_id),
    }
    .insert(database)
    .await?;

    Ok(id)
}

pub async fn insert_revocation_list_entry(
    database: &DatabaseConnection,
    list_id: RevocationListId,
    index: usize,
    credential_id: Option<CredentialId>,
) -> Result<Uuid, DbErr> {
    let id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    let _model = revocation_list_entry::ActiveModel {
        id: Set(id.into()),
        created_date: Set(now),
        revocation_list_id: Set(list_id),
        index: Set(Some(index as _)),
        credential_id: Set(credential_id),
        r#type: Set(credential_id
            .map(|_| RevocationListEntryType::Credential)
            .unwrap_or(RevocationListEntryType::WalletUnitAttestedKey)),
        signature_type: Set(None),
        status: Set(RevocationListEntryStatus::Active),
        serial: Set(None),
    }
    .insert(database)
    .await?;

    Ok(id)
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
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
    }
}

pub async fn insert_wallet_unit_to_database(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
    name: String,
) -> WalletUnitId {
    let id: WalletUnitId = Uuid::new_v4().into();
    let now = get_dummy_date();

    wallet_unit::ActiveModel {
        id: Set(id),
        created_date: Set(now),
        last_modified: Set(now),
        last_issuance: Set(Some(now)),
        name: Set(name),
        os: Set(wallet_unit::WalletUnitOs::Android),
        status: Set(wallet_unit::WalletUnitStatus::Active),
        wallet_provider_type: Set(WalletProviderType::ProcivisOne.into()),
        wallet_provider_name: Set("Test Provider Name".to_string()),
        // Generate unique public key to avoid constraint violations
        authentication_key_jwk: Set(Some(random_jwk_string())),
        nonce: Set(None),
        organisation_id: Set(organisation_id),
    }
    .insert(db)
    .await
    .unwrap();

    id
}

pub async fn insert_wallet_unit_attested_key_to_database(
    db: &DatabaseConnection,
    wallet_unit_id: WalletUnitId,
    revocation_list_entry_id: Option<Uuid>,
    expiration_date: OffsetDateTime,
) -> WalletUnitAttestedKeyId {
    let id = Uuid::new_v4().into();
    wallet_unit_attested_key::ActiveModel {
        id: Set(id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        expiration_date: Set(expiration_date),
        public_key_jwk: Set(random_jwk_string()),
        wallet_unit_id: Set(wallet_unit_id),
        revocation_list_entry_id: Set(revocation_list_entry_id.map(|id| id.into())),
    }
    .insert(db)
    .await
    .unwrap();

    id
}

pub fn random_jwk_string() -> String {
    serde_json::to_string(&random_jwk()).unwrap()
}

pub fn random_jwk() -> PublicJwk {
    let unique_suffix = Ecdsa.generate_key().unwrap();
    unique_suffix.key.public_key_as_jwk().unwrap()
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
