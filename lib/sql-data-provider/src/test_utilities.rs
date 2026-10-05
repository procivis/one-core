#![expect(clippy::unwrap_used)]

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use one_core::model::credential::{Credential, CredentialCommon, CredentialStateEnum};
use one_core::model::organisation::Organisation;
use one_core::model::relation::Related;
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QueryOrder,
    Set,
};
use shared_types::{
    BlobId, CertificateId, ClaimId, ClaimSchemaId, CredentialId, CredentialSchemaFormatId,
    CredentialSchemaId, DidId, DidMethodId, DidValue, EntityId, HistoryId, IdentifierId,
    InteractionId, KeyId, ManagedInstanceAttestationId, ManagedInstanceId, NonceId, OrganisationId,
    ProofId, ProofSchemaId, RevocationListEntryId, RevocationListId, RevocationMethodId,
    TrustCollectionId, TrustListSubscriptionId,
};
use similar_asserts::assert_eq;
use standardized_types::jwk::PublicJwk;
use time::macros::datetime;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::entity::blob::BlobType;
use crate::entity::credential::{CredentialRole, CredentialType};
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::did::DidType;
use crate::entity::history::{self, HistoryAction, HistoryEntityType};
use crate::entity::interaction::InteractionType;
use crate::entity::key_did::KeyRole;
use crate::entity::proof::{ProofRequestState, ProofRole};
use crate::entity::revocation_list::{RevocationListFormat, RevocationListPurpose};
use crate::entity::revocation_list_entry::{RevocationListEntryState, RevocationListEntryType};
use crate::entity::wallet_attestation::AttestationType;
use crate::entity::{
    blob, claim, claim_schema, credential, credential_schema, credential_schema_format, did,
    identifier, instance, interaction, key, key_did, managed_instance,
    managed_instance_attestation, organisation, proof, proof_claim, proof_input_claim_schema,
    proof_input_schema, proof_schema, revocation_list, revocation_list_entry, trust_collection,
    trust_list_subscription, used_nonce,
};
use crate::{DataLayer, db_conn};

#[cfg(test)]
pub fn track_count_queries(db: &mut DatabaseConnection) -> Arc<std::sync::atomic::AtomicUsize> {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let counts = Arc::new(AtomicUsize::new(0));
    let callback_counts = counts.clone();
    db.set_metric_callback(move |info| {
        if info.statement.sql.contains("num_items") {
            callback_counts.fetch_add(1, Ordering::Relaxed);
        }
    });
    counts
}

pub fn get_dummy_date() -> OffsetDateTime {
    datetime!(2005-04-02 21:37 UTC)
}

fn credential_schema_repository(db: &DatabaseConnection) -> Arc<dyn CredentialSchemaRepository> {
    let transaction_manager = crate::transaction_context::TransactionManagerImpl::new(db.clone());
    Arc::new(crate::credential_schema::CredentialSchemaProvider {
        db: transaction_manager.clone(),
        organisation_repository: Arc::new(crate::organisation::OrganisationProvider {
            db: transaction_manager.clone(),
        }),
        localized_text_repository: Arc::new(crate::localized_text::LocalizedTextProvider {
            db: transaction_manager,
        }),
    })
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
    role: CredentialRole,
) -> Result<Credential, DbErr> {
    let now = one_core::clock::now_utc();

    blob::ActiveModel {
        id: Set(credential_blob_id),
        created_date: Set(now),
        last_modified: Set(now),
        value: Set(vec![0, 0, 0, 0]),
        r#type: Set(BlobType::Credential),
    }
    .insert(db)
    .await?;

    let organisation_id = credential_schema::Entity::find_by_id(*credential_schema_id)
        .one(db)
        .await?
        .ok_or(DbErr::RecordNotFound(credential_schema_id.to_string()))?
        .organisation_id;

    let key_id = if role == CredentialRole::Issuer {
        Some(
            insert_key_to_database(db, "EDDSA".into(), vec![], vec![], None, organisation_id)
                .await?,
        )
    } else {
        None
    };
    let format_id = credential_schema_format::Entity::find()
        .filter(credential_schema_format::Column::CredentialSchemaId.eq(*credential_schema_id))
        .one(db)
        .await?
        .map(|format| format.id);

    let credential = credential::ActiveModel {
        expires_at: Set(None),
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        credential_schema_id: Set(*credential_schema_id),
        organisation_id: Set(organisation_id),
        created_date: Set(now),
        last_modified: Set(now),
        issuance_date: Set(None),
        redirect_uri: Set(None),
        deleted_at: Set(deleted_at),
        consumed_at: Set(None),
        protocol: Set(protocol.to_owned()),
        role: Set(role),
        r#type: Set(CredentialType::Single),
        issuer_identifier_id: Set(Some(issuer_identifier_id)),
        issuer_certificate_id: Set(None),
        holder_identifier_id: Set(None),
        interaction_id: Set(None),
        key_id: Set(key_id),
        state: Set(state.into()),
        suspend_end_date: Set(suspend_end_date),
        profile: Set(None),
        parent_id: Set(None),
        credential_blob_id: Set(Some(credential_blob_id)),
        wallet_key_attestation_blob_id: Set(None),
        wallet_instance_attestation_blob_id: Set(None),
        webhook_url: Set(None),
        embedded_disclosure_policy: Set(None),
        subscriber_information: Set(None),
        format: Set(format_id),
    }
    .insert(db)
    .await?;

    Ok(Credential::Generic {
        common: CredentialCommon {
            expires_at: None,
            ecosystem: None,
            id: credential.id,
            created_date: credential.created_date,
            issuance_date: credential.issuance_date,
            last_modified: credential.last_modified,
            deleted_at: credential.deleted_at,
            protocol: credential.protocol,
            redirect_uri: credential.redirect_uri,
            state: credential.state.into(),
            profile: credential.profile,
            schema: Related::new(*credential_schema_id, credential_schema_repository(db)),
            interaction: None,
        },
        consumed_at: credential.consumed_at,
        role: credential.role.into(),
        r#type: credential.r#type.into(),
        suspend_end_date: credential.suspend_end_date,
        claims: Default::default(),
        issuer_identifier: None,
        issuer_certificate: None,
        holder_identifier: None,
        key: None,
        credential_blob_id: credential.credential_blob_id,
        wallet_key_attestation_blob_id: credential.wallet_key_attestation_blob_id,
        wallet_instance_attestation_blob_id: credential.wallet_instance_attestation_blob_id,
        webhook_url: credential.webhook_url,
        embedded_disclosure_policy: credential.embedded_disclosure_policy,
        subscriber_information: credential.subscriber_information,
        parent: None,
        format: None,
    })
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
    allow_revocation: bool,
    key_storage_security: Option<KeyStorageSecurity>,
) -> Result<CredentialSchemaId, DbErr> {
    let new_id: CredentialSchemaId = Uuid::new_v4().into();
    let schema = credential_schema::ActiveModel {
        expiration: Set(None),
        ecosystem: Set(None),
        batch_size: Set(None),
        preferred_key_storage_attestation_lifetime: Set(None),
        preferred_instance_attestation_lifetime: Set(None),
        allow_revocation: Set(allow_revocation),
        id: Set(new_id.to_owned()),
        imported_source_url: Set("CORE_URL".to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        name: Set(name.to_owned()),
        organisation_id: Set(organisation_id),
        key_storage_security: Set(key_storage_security),
        deleted_at: Set(deleted_at),
        layout_properties: Set(None),
        allow_suspension: Set(true),
        requires_wallet_instance_attestation: Set(key_storage_security.is_some()),
        transaction_code_type: Set(None),
        transaction_code_length: Set(None),
        transaction_code_description: Set(None),
        embedded_disclosure_policy: Set(None),
    }
    .insert(database)
    .await?;
    Ok(schema.id)
}

pub async fn insert_credential_schema_with_revocation_to_database(
    database: &DatabaseConnection,
    credential_schema_id: CredentialSchemaId,
    format: &str,
) -> Result<CredentialSchemaFormatId, DbErr> {
    let credential_schema_format = credential_schema_format::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        credential_schema_id: Set(credential_schema_id),
        format: Set(format.into()),
        ecosystem_schema_id: Set(credential_schema_id.to_string()),
    }
    .insert(database)
    .await?;
    Ok(credential_schema_format.id)
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
        |(id, claim_schema_id, _, value, path, selectively_disclosable)| claim::ActiveModel {
            id: Set(*id),
            claim_schema_id: Set(*claim_schema_id),
            value: Set(value.to_owned()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            path: Set(path.to_owned()),
            selectively_disclosable: Set(*selectively_disclosable),
        },
    );

    claim::Entity::insert_many(models).exec(database).await?;
    crate::entity::credential_claim::Entity::insert_many(claims.iter().map(
        |(id, _, credential_id, _, _, _)| crate::entity::credential_claim::ActiveModel {
            credential_id: Set(*credential_id),
            claim_id: Set(*id),
        },
    ))
    .exec(database)
    .await?;
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
            order: Set(claim_schema.order as i32),
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

#[expect(clippy::too_many_arguments)]
pub async fn insert_proof_request_to_database(
    database: &DatabaseConnection,
    verifier_identifier_id: IdentifierId,
    proof_schema_id: &ProofSchemaId,
    verifier_key_id: KeyId,
    interaction_id: Option<InteractionId>,
    proof_blob_id: Option<BlobId>,
    engagement: Option<String>,
    role: ProofRole,
) -> Result<ProofId, DbErr> {
    let proof = proof::ActiveModel {
        ecosystem: Set(None),
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        protocol: Set("OPENID4VP_FINAL1".to_string()),
        transport: Set("HTTP".to_string()),
        redirect_uri: Set(None),
        state: Set(ProofRequestState::Created),
        role: Set(role),
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
        webhook_url: Set(None),
        subscriber_information: Set(None),
    }
    .insert(database)
    .await?;
    Ok(proof.id)
}

pub struct ClaimInsertInfo<'a> {
    pub id: ClaimSchemaId,
    pub key: String,
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
        ecosystem: Set(None),
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
        let formats = credential_schema_format::Entity::find()
            .filter(
                credential_schema_format::Column::CredentialSchemaId.eq(input.credential_schema_id),
            )
            .order_by_asc(credential_schema_format::Column::Format)
            .all(database)
            .await?
            .into_iter()
            .map(|format| format.format.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let input_id = proof_input_schema::ActiveModel {
            formats: Set(formats),
            id: NotSet,
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            order: Set(i as _),
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
        ecosystem: Set(None),
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
    proof_claims: &[(ProofId, CredentialId, ClaimId)],
) -> Result<(), DbErr> {
    let mut models = Vec::with_capacity(proof_claims.len());
    for (proof_id, credential_id, claim_id) in proof_claims {
        models.push(proof_claim::ActiveModel {
            claim_id: Set(*claim_id),
            proof_id: Set(*proof_id),
            credential_id: Set(*credential_id),
        });
    }

    proof_claim::Entity::insert_many(models)
        .exec(database)
        .await?;

    Ok(())
}

pub async fn insert_organisation_to_database(
    database: &DatabaseConnection,
    id: Option<OrganisationId>,
) -> Result<OrganisationId, DbErr> {
    let id = id.unwrap_or(Uuid::new_v4().into());
    let organisation = organisation::ActiveModel {
        id: Set(id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        deactivated_at: NotSet,
        wallet_provider: NotSet,
        wallet_provider_issuer: NotSet,
        parent_organisation: NotSet,
        configuration: NotSet,
        verifier_provider: NotSet,
        verifier_provider_issuer: NotSet,
    }
    .insert(database)
    .await?;
    Ok(organisation.id)
}

pub async fn insert_blob_to_database(
    database: &DatabaseConnection,
    id: Option<BlobId>,
    r#type: BlobType,
    value: Option<Vec<u8>>,
) -> Result<BlobId, DbErr> {
    let id = id.unwrap_or(Uuid::new_v4().into());
    let blob = blob::ActiveModel {
        id: Set(id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        value: Set(value.unwrap_or_default()),
        r#type: Set(r#type),
    }
    .insert(database)
    .await?;
    Ok(blob.id)
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
        name: Set(format!("{}-key", id).to_owned()),
        public_key: Set(public_key),
        key_reference: Set(Some(key_reference)),
        storage_type: Set("INTERNAL".to_string()),
        key_type: Set(key_type),
        autogenerated: Set(false),
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
    method: impl Into<DidMethodId>,
    did_type: DidType,
    deactivated: impl Into<Option<bool>>,
) -> Result<DidId, DbErr> {
    let now = one_core::clock::now_utc();

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
    let now = one_core::clock::now_utc();

    let identifier = identifier::ActiveModel {
        id: Set(identifier_id.into()),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set(name.to_owned()),
        organisation_id: Set(organisation_id),
        deleted_at: NotSet,
        r#type: Set(identifier::IdentifierType::Did),
        is_remote: Set(remote.into()),
        state: Set(identifier::IdentifierState::Active),
        did_id: Set(did_id),
        key_id: NotSet,
        autogenerated: Set(name.starts_with("autogenerated-")),
        logo: NotSet,
    }
    .insert(database)
    .await?;

    Ok(identifier.id)
}

pub async fn insert_interaction(
    database: &DatabaseConnection,
    data: &[u8],
    organisation_id: OrganisationId,
    interaction_type: InteractionType,
) -> Result<InteractionId, DbErr> {
    let now = one_core::clock::now_utc();

    let interaction = interaction::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(now),
        last_modified: Set(now),
        data: Set(Some(data.to_owned())),
        organisation_id: Set(organisation_id),
        interaction_type: Set(interaction_type),
        expires_at: Set(None),
        ecosystem: Set(None),
        ecosystem_data: Set(None),
    }
    .insert(database)
    .await?;

    Ok(interaction.id)
}

pub async fn insert_used_nonce(
    database: &DatabaseConnection,
    nonce_id: NonceId,
    interaction_id: InteractionId,
) -> Result<(), DbErr> {
    let now = one_core::clock::now_utc();

    used_nonce::ActiveModel {
        id: Set(nonce_id),
        created_date: Set(now),
        interaction_id: Set(interaction_id),
    }
    .insert(database)
    .await?;

    Ok(())
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
    let now = one_core::clock::now_utc();

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
        metadata_blob_id: Set(None),
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
    r#type: RevocationMethodId,
    issuer_certificate_id: Option<CertificateId>,
) -> Result<RevocationListId, DbErr> {
    let id = Uuid::new_v4().into();
    let now = one_core::clock::now_utc();

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
) -> Result<RevocationListEntryId, DbErr> {
    let id = Uuid::new_v4().into();
    let now = one_core::clock::now_utc();

    let _model = revocation_list_entry::ActiveModel {
        id: Set(id),
        created_date: Set(now),
        last_modified: Set(now),
        revocation_list_id: Set(list_id),
        index: Set(Some(index as _)),
        credential_id: Set(credential_id),
        r#type: Set(credential_id
            .map(|_| RevocationListEntryType::Credential)
            .unwrap_or(RevocationListEntryType::KeyAttestation)),
        signature_type: Set(None),
        state: Set(RevocationListEntryState::Active),
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
        id,
        created_date: one_core::clock::now_utc(),
        last_modified: one_core::clock::now_utc(),
        deactivated_at: None,
        wallet_provider: None,
        wallet_provider_issuer: None,
        parent_organisation: None,
        verifier_provider: None,
        verifier_provider_issuer: None,
        configuration: Default::default(),
    }
}

pub async fn insert_wallet_instance_to_database(
    db: &DatabaseConnection,
    organisation_id: OrganisationId,
    name: String,
) -> ManagedInstanceId {
    let id: ManagedInstanceId = Uuid::new_v4().into();
    let now = get_dummy_date();

    managed_instance::ActiveModel {
        id: Set(id),
        created_date: Set(now),
        last_modified: Set(now),
        last_issuance: Set(Some(now)),
        name: Set(name),
        os: Set(managed_instance::ManagedInstanceOs::Android),
        status: Set(instance::InstanceStatus::Active),
        provider: Set("Test Provider Name".to_string()),
        // Generate unique public key to avoid constraint violations
        authentication_key_jwk: Set(Some(random_jwk_string())),
        nonce: Set(None),
        user_nonce: Set(None),
        user_sub: Set(None),
        organisation_id: Set(organisation_id),
        role: Set(instance::InstanceRole::Wallet),
        verifier_csr: Set(None),
        verifier_signature_ids: Set(None),
        version: Set(None),
    }
    .insert(db)
    .await
    .unwrap();

    id
}

pub async fn insert_wallet_unit_attested_key_to_database(
    db: &DatabaseConnection,
    managed_instance_id: ManagedInstanceId,
    revocation_list_entry_id: Option<Uuid>,
    expiration_date: OffsetDateTime,
) -> ManagedInstanceAttestationId {
    let id = Uuid::new_v4().into();
    managed_instance_attestation::ActiveModel {
        id: Set(id),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        expiration_date: Set(expiration_date),
        r#type: Set(AttestationType::KeyAttestation),
        attestation_content_hash: Set(None),
        managed_instance_id: Set(managed_instance_id),
        revocation_list_entry_id: Set(revocation_list_entry_id.map(|id| id.into())),
    }
    .insert(db)
    .await
    .unwrap();

    id
}

pub async fn insert_trust_collection_to_database(
    database: &DatabaseConnection,
    organisation_id: OrganisationId,
) -> Result<TrustCollectionId, DbErr> {
    let id = Uuid::new_v4().into();
    let collection = trust_collection::ActiveModel {
        ecosystem: Set("EUDI".into()),
        id: Set(id),
        name: Set(id.to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        remote_trust_collection_url: NotSet,
        deactivated_at: NotSet,
        organisation_id: Set(organisation_id),
    }
    .insert(database)
    .await?;
    Ok(collection.id)
}

pub async fn insert_trust_list_subscription_to_database(
    database: &DatabaseConnection,
    trust_collection_id: TrustCollectionId,
) -> Result<TrustListSubscriptionId, DbErr> {
    let id = Uuid::new_v4().into();
    let subscription = trust_list_subscription::ActiveModel {
        id: Set(id),
        name: Set(id.to_string()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(get_dummy_date()),
        deactivated_at: NotSet,
        r#type: Set("LoTE".into()),
        reference: Set(format!("https://example.com/trust-list/{id}")),
        role: NotSet,
        state: Set(trust_list_subscription::TrustListSubscriptionState::Active),
        trust_collection_id: Set(trust_collection_id),
    }
    .insert(database)
    .await?;
    Ok(subscription.id)
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
