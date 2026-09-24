use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use one_core::model::credential::Credential;
use one_core::model::identifier::Identifier;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::proof::{GetProofList, Proof, ProofClaim, SortableProofColumn};
use one_core::model::proof_schema::ProofSchema;
use one_core::model::relation::{AsyncVecLoader, OptionalRelatedExt, Related, RelatedVec};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::ClaimRepository;
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use one_core::service::proof::dto::ProofFilterValue;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::{ColumnRef, IntoCondition};
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter, Set};
use shared_types::{ClaimId, CredentialId, ProofId};

use super::model::ProofListItemModel;
use crate::common::calculate_pages_count;
use crate::entity::proof::{ProofRequestState, ProofRole};
use crate::entity::{identifier, interaction, proof, proof_claim, proof_schema};
use crate::identifier::mapper::{
    identifier_data_from_ids, identifier_localized_text, identifier_trust_information,
};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_comparison_condition,
    get_string_match_condition,
};
use crate::transaction_context::TransactionManagerImpl;

impl IntoSortingColumn for SortableProofColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => ColumnSortingBehavior::default(proof::Column::CreatedDate),
            Self::SchemaName => ColumnSortingBehavior::case_insensitive(proof_schema::Column::Name),
            Self::Verifier => ColumnSortingBehavior::case_insensitive(identifier::Column::Name),
            Self::State => ColumnSortingBehavior::default(proof::Column::State),
        }
    }
}

/// Decides whether to SQL-JOIN related interactions (which we need to filter by organisation on the holder side)
pub(super) fn needs_interaction_table_for_filter(
    filter: Option<&ListFilterCondition<ProofFilterValue>>,
) -> bool {
    let Some(filter) = filter else {
        return false;
    };

    let has_organisation_filter =
        filter.contains(&|fv| matches!(fv, ProofFilterValue::OrganisationId(_)));

    let has_verifier_only_role_filter = filter.contains(&|fv| {
        let ProofFilterValue::Roles(roles) = fv else {
            return false;
        };

        roles
            .iter()
            .all(|role| role == &one_core::model::proof::ProofRole::Verifier)
    });

    has_organisation_filter && !has_verifier_only_role_filter
}

impl IntoFilterCondition for ProofFilterValue {
    fn get_condition(self, entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(proof_schema::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                if needs_interaction_table_for_filter(Some(entire_filter)) {
                    proof_schema::Column::OrganisationId
                        .eq(organisation_id)
                        .or(interaction::Column::OrganisationId.eq(organisation_id))
                } else {
                    proof_schema::Column::OrganisationId.eq(organisation_id)
                }
                .into_condition()
            }
            Self::States(states) => proof::Column::State
                .is_in(states.into_iter().map(ProofRequestState::from))
                .into_condition(),
            Self::Roles(roles) => proof::Column::Role
                .is_in(roles.into_iter().map(ProofRole::from))
                .into_condition(),
            Self::ProofSchemaIds(ids) => proof_schema::Column::Id.is_in(ids).into_condition(),
            Self::ProofIds(ids) => proof::Column::Id.is_in(ids).into_condition(),
            Self::ProofIdsNot(ids) => proof::Column::Id.is_not_in(ids).into_condition(),
            Self::VerifierIds(ids) => proof::Column::VerifierIdentifierId
                .is_in(ids)
                .into_condition(),
            Self::ValidForDeletion => proof_schema::Column::ExpireDuration.gt(0).into_condition(),
            Self::Profiles(profiles) => proof::Column::Profile
                .is_in(profiles.iter())
                .into_condition(),
            Self::Ecosystems(ecosystems) => proof::Column::Ecosystem
                .is_in(ecosystems.iter())
                .into_condition(),
            Self::CreatedDate(value) => get_comparison_condition(proof::Column::CreatedDate, value),
            Self::LastModified(value) => {
                get_comparison_condition(proof::Column::LastModified, value)
            }
            Self::RequestedDate(value) => {
                get_comparison_condition(proof::Column::RequestedDate, value)
            }
            Self::CompletedDate(value) => {
                get_comparison_condition(proof::Column::CompletedDate, value)
            }
        }
    }
}

#[expect(clippy::too_many_arguments)]
fn proof_from_list_item_model(
    value: ProofListItemModel,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    did_repository: &Arc<dyn DidRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
    trust_information_repository: &Arc<dyn IdentifierTrustInformationRepository>,
    claim_repository: &Arc<dyn ClaimRepository>,
    credential_repository: &Arc<dyn CredentialRepository>,
    localized_text_repository: &Arc<dyn LocalizedTextRepository>,
    db: &TransactionManagerImpl,
) -> Result<Proof, DataLayerError> {
    let verifier_identifier = match value.verifier_identifier_id {
        None => None,
        Some(verifier_identifier_id) => Some(Identifier {
            id: verifier_identifier_id,
            created_date: value
                .verifier_identifier_created_date
                .ok_or(DataLayerError::MappingError)?,
            last_modified: value
                .verifier_identifier_last_modified
                .ok_or(DataLayerError::MappingError)?,
            name: value
                .verifier_identifier_name
                .ok_or(DataLayerError::MappingError)?,
            data: identifier_data_from_ids(
                value
                    .verifier_identifier_type
                    .ok_or(DataLayerError::MappingError)?
                    .into(),
                verifier_identifier_id,
                value.verifier_identifier_did_id,
                value.verifier_identifier_key_id,
                did_repository,
                key_repository,
                certificate_repository,
            )?,
            organisation: Related::new(
                value
                    .verifier_identifier_organisation_id
                    .ok_or(DataLayerError::MappingError)?,
                organisation_repository.to_owned(),
            ),
            is_remote: value
                .verifier_identifier_is_remote
                .ok_or(DataLayerError::MappingError)?,
            state: value
                .verifier_identifier_state
                .ok_or(DataLayerError::MappingError)?
                .into(),
            deleted_at: None,
            trust_information: identifier_trust_information(
                verifier_identifier_id,
                trust_information_repository,
            ),
            autogenerated: value
                .verifier_identifier_autogenerated
                .ok_or(DataLayerError::MappingError)?,
            logo: value.verifier_identifier_logo,
            translations: identifier_localized_text(
                verifier_identifier_id,
                localized_text_repository,
            ),
        }),
    };

    let schema = match value.schema_id {
        None => None,
        Some(schema_id) => Some(ProofSchema {
            id: schema_id,
            created_date: value
                .schema_created_date
                .ok_or(DataLayerError::MappingError)?,
            last_modified: value
                .schema_last_modified
                .ok_or(DataLayerError::MappingError)?,
            deleted_at: None,
            name: value.schema_name.ok_or(DataLayerError::MappingError)?,
            expire_duration: value
                .schema_expire_duration
                .ok_or(DataLayerError::MappingError)? as u32,
            imported_source_url: value.schema_imported_source_url,
            ecosystem: value.schema_ecosystem,
            organisation: Related::new(
                value
                    .schema_organisation_id
                    .ok_or(DataLayerError::MappingError)?,
                organisation_repository.clone(),
            ),
            input_schemas: Default::default(),
        }),
    };

    Ok(Proof {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        protocol: value.protocol,
        transport: value.transport,
        redirect_uri: value.redirect_uri,
        state: value.state.into(),
        role: value.role.into(),
        requested_date: value.requested_date,
        completed_date: value.completed_date,
        profile: value.profile,
        schema: convert_inner(schema),
        claims: RelatedVec::new(ProofClaimsLoader {
            db: db.clone(),
            id: value.id,
            claim_repository: claim_repository.clone(),
            credential_repository: credential_repository.clone(),
        }),
        verifier_identifier: convert_inner(verifier_identifier),
        verifier_key: None,
        verifier_certificate: None,
        interaction: None,
        proof_blob_id: value.proof_blob_id,
        engagement: value.engagement,
        webhook_url: value.webhook_url,
        subscriber_information: value.subscriber_information,
        ecosystem: value.ecosystem,
    })
}

#[expect(clippy::too_many_arguments)]
pub(super) fn proof_model_to_repository(
    value: proof::Model,
    credential_repository: &Arc<dyn CredentialRepository>,
    claim_repository: &Arc<dyn ClaimRepository>,
    proof_schema_repository: &Arc<dyn ProofSchemaRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    db: &TransactionManagerImpl,
) -> Proof {
    Proof {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        protocol: value.protocol,
        transport: value.transport,
        redirect_uri: value.redirect_uri,
        state: value.state.into(),
        role: value.role.into(),
        requested_date: value.requested_date,
        completed_date: value.completed_date,
        profile: value.profile,
        proof_blob_id: value.proof_blob_id,
        engagement: value.engagement,
        schema: value
            .proof_schema_id
            .map(|proof_schema_id| Related::new(proof_schema_id, proof_schema_repository.clone())),
        claims: RelatedVec::new(ProofClaimsLoader {
            db: db.clone(),
            id: value.id,
            claim_repository: claim_repository.clone(),
            credential_repository: credential_repository.clone(),
        }),
        verifier_identifier: value.verifier_identifier_id.map(|verifier_identifier_id| {
            Related::new(verifier_identifier_id, identifier_repository.clone())
        }),
        verifier_key: value
            .verifier_key_id
            .map(|verifier_key_id| Related::new(verifier_key_id, key_repository.clone())),
        verifier_certificate: value
            .verifier_certificate_id
            .map(|verifier_certificate_id| {
                Related::new(verifier_certificate_id, certificate_repository.clone())
            }),
        interaction: value
            .interaction_id
            .map(|interaction_id| Related::new(interaction_id, interaction_repository.clone())),
        webhook_url: value.webhook_url,
        subscriber_information: value.subscriber_information,
        ecosystem: value.ecosystem,
    }
}

impl TryFrom<Proof> for proof::ActiveModel {
    type Error = DataLayerError;
    fn try_from(value: Proof) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            transport: Set(value.transport),
            redirect_uri: Set(value.redirect_uri),
            protocol: Set(value.protocol),
            state: Set(value.state.into()),
            role: Set(value.role.into()),
            requested_date: Set(value.requested_date),
            completed_date: Set(value.completed_date),
            verifier_identifier_id: Set(value.verifier_identifier.id_opt()),
            proof_schema_id: Set(value.schema.id_opt()),
            verifier_key_id: Set(value.verifier_key.id_opt()),
            verifier_certificate_id: Set(value.verifier_certificate.id_opt()),
            interaction_id: Set(value.interaction.id_opt()),
            profile: Set(value.profile),
            proof_blob_id: Set(value.proof_blob_id),
            engagement: Set(value.engagement),
            webhook_url: Set(value.webhook_url),
            subscriber_information: Set(value.subscriber_information),
            ecosystem: Set(value.ecosystem),
        })
    }
}

#[expect(clippy::too_many_arguments)]
pub(super) fn create_list_response(
    proofs: Vec<ProofListItemModel>,
    limit: Option<u64>,
    items_count: Option<u64>,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    did_repository: &Arc<dyn DidRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
    trust_information_repository: &Arc<dyn IdentifierTrustInformationRepository>,
    claim_repository: &Arc<dyn ClaimRepository>,
    credential_repository: &Arc<dyn CredentialRepository>,
    localized_text_repository: &Arc<dyn LocalizedTextRepository>,
    db: &TransactionManagerImpl,
) -> Result<GetProofList, DataLayerError> {
    let values = proofs
        .into_iter()
        .map(|proof| {
            proof_from_list_item_model(
                proof,
                organisation_repository,
                did_repository,
                key_repository,
                certificate_repository,
                trust_information_repository,
                claim_repository,
                credential_repository,
                localized_text_repository,
                db,
            )
        })
        .collect::<Result<Vec<Proof>, DataLayerError>>()?;

    Ok(GetProofList {
        values,
        total_pages: items_count.map(|count| calculate_pages_count(count, limit.unwrap_or(count))),
        total_items: items_count,
    })
}

pub(super) fn get_proof_claim_active_model(
    proof_id: ProofId,
    claim: &ProofClaim,
) -> proof_claim::ActiveModel {
    proof_claim::ActiveModel {
        proof_id: Set(proof_id),
        claim_id: Set(claim.claim.id),
        credential_id: Set(claim.credential.id()),
    }
}

struct ProofClaimsLoader {
    db: TransactionManagerImpl,
    id: ProofId,
    claim_repository: Arc<dyn ClaimRepository>,
    credential_repository: Arc<dyn CredentialRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ProofClaim> for ProofClaimsLoader {
    async fn load(&self) -> Result<Vec<ProofClaim>, DataLayerError> {
        let proof_claims = proof_claim::Entity::find()
            .filter(proof_claim::Column::ProofId.eq(self.id))
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        // Different presented credentials can reference the same inherited claim.
        let claim_ids: HashSet<ClaimId> = proof_claims.iter().map(|item| item.claim_id).collect();
        if claim_ids.is_empty() {
            return Ok(vec![]);
        }

        let claims: HashMap<_, _> = self
            .claim_repository
            .get_claim_list(claim_ids.into_iter().collect())
            .await?
            .into_iter()
            .map(|claim| (claim.id, claim))
            .collect();
        let mut credential_relations: HashMap<CredentialId, Related<Credential>> = HashMap::new();
        proof_claims
            .into_iter()
            .map(|proof_claim| {
                let claim = claims.get(&proof_claim.claim_id).cloned().ok_or_else(|| {
                    DataLayerError::Db(anyhow::anyhow!(
                        "Missing claim {} for proof {}",
                        proof_claim.claim_id,
                        self.id
                    ))
                })?;
                let credential = credential_relations
                    .entry(proof_claim.credential_id)
                    .or_insert_with(|| {
                        Related::new(
                            proof_claim.credential_id,
                            self.credential_repository.clone(),
                        )
                    })
                    .to_owned();

                Ok(ProofClaim { claim, credential })
            })
            .collect()
    }
}
