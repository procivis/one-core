use std::sync::Arc;

use one_core::model::claim::Claim;
use one_core::model::credential::{
    Clearable, Credential, CredentialFilterValue, SortableCredentialColumn,
};
use one_core::model::credential_schema::{CredentialSchema, LayoutType, TransactionCode};
use one_core::model::identifier::Identifier;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::{Related, RelatedVec};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::claim_repository::{ClaimRepository, CredentialClaimsLoader};
use one_core::repository::credential_repository::CredentialRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::did_repository::DidRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::identifier_trust_information_repository::IdentifierTrustInformationRepository;
use one_core::repository::interaction_repository::InteractionRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::sea_query::{ExprTrait, Query, SelectStatement, SimpleExpr};
use sea_orm::{ActiveValue, ColumnTrait, IntoSimpleExpr, JoinType, RelationTrait, Set, Value};
use shared_types::{BlobId, CertificateId, CredentialId, IdentifierId, InteractionId, KeyId};
use time::Duration;

use crate::TransactionManagerImpl;
use crate::credential::entity_model::CredentialListEntityModel;
use crate::credential_schema::mapper::{ClaimSchemasLoader, CredentialSchemaFormatsLoader};
use crate::entity::{claim, credential, credential_schema, credential_schema_format, identifier};
use crate::identifier::mapper::{identifier_data_from_ids, identifier_trust_information};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_blob_match_condition, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};
use crate::localized_text::LocalizedTextLoader;

pub(super) fn from_clearable<T>(clearable: Clearable<Option<T>>) -> ActiveValue<Option<T>>
where
    Option<T>: Into<Value>,
{
    match clearable {
        Clearable::ForceSet(value) => Set(value),
        Clearable::DontTouch => ActiveValue::Unchanged(Default::default()),
    }
}

impl IntoSortingColumn for SortableCredentialColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => credential::Column::CreatedDate.into_simple_expr(),
            Self::SchemaName => credential_schema::Column::Name.into_simple_expr(),
            Self::Issuer => identifier::Column::Name.into_simple_expr(),
            Self::State => credential::Column::State.into_simple_expr(),
            Self::ExpiresAt => credential::Column::ExpiresAt.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for CredentialFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::CredentialSchemaName(string_match) => {
                get_string_match_condition(credential_schema::Column::Name, string_match)
            }
            Self::ClaimName(string_match) => {
                get_string_match_condition(claim::Column::Path, string_match)
            }
            Self::ClaimValue(string_match) => {
                get_blob_match_condition(claim::Column::Value, string_match, 255)
            }
            Self::OrganisationId(organisation_id) => get_equals_condition(
                credential_schema::Column::OrganisationId,
                organisation_id.to_string(),
            ),
            Self::Roles(roles) => credential::Column::Role
                .is_in(
                    roles
                        .into_iter()
                        .map(credential::CredentialRole::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::CredentialIds(ids) => credential::Column::Id.is_in(ids.iter()).into_condition(),
            Self::ParentCredential(parent_id) => {
                get_equals_condition(credential::Column::ParentId, parent_id.to_string())
            }
            Self::CredentialSchemaIds(ids) => credential::Column::CredentialSchemaId
                .is_in(ids.iter())
                .into_condition(),
            Self::SchemaId(schema_id) => credential_schema::Column::Id
                .in_subquery(
                    Query::select()
                        .column(credential_schema_format::Column::CredentialSchemaId)
                        .from(credential_schema_format::Entity)
                        .cond_where(get_equals_condition(
                            credential_schema_format::Column::SchemaId,
                            schema_id,
                        ))
                        .to_owned(),
                )
                .into_condition(),
            Self::IssuerIds(ids) => credential::Column::IssuerIdentifierId
                .is_in(ids.iter())
                .into_condition(),
            Self::States(states) => credential::Column::State
                .is_in(
                    states
                        .into_iter()
                        .map(credential::CredentialState::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::Types(types) => credential::Column::Type
                .is_in(
                    types
                        .into_iter()
                        .map(credential::CredentialType::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::Consumed(consumed) => (if consumed {
                credential::Column::ConsumedAt.is_not_null()
            } else {
                credential::Column::ConsumedAt.is_null()
            })
            .into_condition(),
            Self::SuspendEndDate(comparison) => {
                get_comparison_condition(credential::Column::SuspendEndDate, comparison)
            }
            Self::Profiles(profiles) => credential::Column::Profile
                .is_in(profiles.iter())
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(credential::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(credential::Column::LastModified, value)
            }
            Self::IssuanceDate(value) => {
                get_comparison_condition(credential::Column::IssuanceDate, value)
            }
            Self::RevocationDate(value) => {
                get_comparison_condition(credential::Column::LastModified, value)
                    .and(credential::Column::State.eq(credential::CredentialState::Revoked))
                    .into_condition()
            }
            Self::ExpiresAt(value) => {
                get_comparison_condition(credential::Column::ExpiresAt, value)
            }
            Self::HasUnconsumedBatchItems(true) => credential::Column::Id
                .in_subquery(unconsumed_item_select())
                .into_condition(),
            Self::HasUnconsumedBatchItems(false) => credential::Column::Id
                .not_in_subquery(unconsumed_item_select())
                .into_condition(),
            Self::Deleted(false) => credential::Column::DeletedAt.is_null().into_condition(),
            Self::Deleted(true) => credential::Column::DeletedAt.is_not_null().into_condition(),
        }
    }
}

fn unconsumed_item_select() -> SelectStatement {
    Query::select()
        .distinct()
        .column(credential::Column::ParentId)
        .from(credential::Entity)
        .cond_where(
            credential::Column::ConsumedAt
                .is_null()
                .and(credential::Column::State.eq(credential::CredentialState::Accepted)),
        )
        .to_owned()
}

impl IntoJoinRelations for CredentialFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            // add claims if filtering by claim name/value
            Self::ClaimName(_) | Self::ClaimValue(_) => {
                vec![JoinRelation {
                    join_type: JoinType::LeftJoin,
                    relation_def: credential::Relation::Claim.def(),
                    alias: None,
                }]
            }
            _ => vec![],
        }
    }
}

/// Builds the lazily loaded claims relation of a credential. Shared between the credential
/// mapper and the credential list projection.
pub(crate) fn credential_claims(
    credential_id: CredentialId,
    claim_repository: &Arc<dyn ClaimRepository>,
) -> RelatedVec<Claim> {
    RelatedVec::new(CredentialClaimsLoader {
        credential_id,
        claim_repository: claim_repository.to_owned(),
    })
}

#[expect(clippy::too_many_arguments)]
pub(crate) fn model_to_credential(
    credential: credential::Model,
    credential_repository: &Arc<dyn CredentialRepository>,
    claim_repository: &Arc<dyn ClaimRepository>,
    credential_schema_repository: &Arc<dyn CredentialSchemaRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
) -> Credential {
    Credential {
        claims: credential_claims(credential.id, claim_repository),
        id: credential.id,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        expires_at: credential.expires_at,
        last_modified: credential.last_modified,
        deleted_at: credential.deleted_at,
        consumed_at: credential.consumed_at,
        protocol: credential.protocol,
        redirect_uri: credential.redirect_uri,
        role: credential.role.into(),
        r#type: credential.r#type.into(),
        state: credential.state.into(),
        suspend_end_date: credential.suspend_end_date,
        profile: credential.profile,
        issuer_identifier: credential
            .issuer_identifier_id
            .map(|id| Related::new(id, identifier_repository.clone())),
        issuer_certificate: credential
            .issuer_certificate_id
            .map(|id| Related::new(id, certificate_repository.clone())),
        holder_identifier: credential
            .holder_identifier_id
            .map(|id| Related::new(id, identifier_repository.clone())),
        schema: Related::new(
            credential.credential_schema_id,
            credential_schema_repository.clone(),
        ),
        interaction: credential
            .interaction_id
            .map(|id| Related::new(id, interaction_repository.clone())),
        key: credential
            .key_id
            .map(|id| Related::new(id, key_repository.clone())),
        credential_blob_id: credential.credential_blob_id,
        wallet_unit_attestation_blob_id: credential.wallet_unit_attestation_blob_id,
        wallet_instance_attestation_blob_id: credential.wallet_instance_attestation_blob_id,
        webhook_url: credential.webhook_url,
        embedded_disclosure_policy: credential.embedded_disclosure_policy,
        subscriber_information: credential.subscriber_information,
        ecosystem: credential.ecosystem,
        parent: credential
            .parent_id
            .map(|id| Related::new(id, credential_repository.clone())),
    }
}

#[expect(clippy::too_many_arguments)]
pub(super) fn request_to_active_model(
    request: &Credential,
    issuer_identifier_id: Option<IdentifierId>,
    issuer_certificate_id: Option<CertificateId>,
    holder_identifier_id: Option<IdentifierId>,
    interaction_id: Option<InteractionId>,
    key_id: Option<KeyId>,
    credential_blob_id: Option<BlobId>,
    wallet_unit_attestation_blob_id: Option<BlobId>,
    wallet_instance_attestation_blob_id: Option<BlobId>,
) -> credential::ActiveModel {
    credential::ActiveModel {
        id: Set(request.id),
        credential_schema_id: Set(request.schema.id()),
        created_date: Set(request.created_date),
        last_modified: Set(request.last_modified),
        issuance_date: Set(request.issuance_date),
        expires_at: Set(request.expires_at),
        deleted_at: Set(request.deleted_at),
        consumed_at: Set(request.consumed_at),
        protocol: Set(request.protocol.to_owned()),
        redirect_uri: Set(request.redirect_uri.to_owned()),
        issuer_identifier_id: Set(issuer_identifier_id),
        issuer_certificate_id: Set(issuer_certificate_id),
        holder_identifier_id: Set(holder_identifier_id),
        interaction_id: Set(interaction_id),
        key_id: Set(key_id),
        role: Set(request.role.to_owned().into()),
        state: Set(request.state.into()),
        suspend_end_date: Set(request.suspend_end_date),
        profile: Set(request.profile.clone()),
        parent_id: Set(request.parent.as_ref().map(|m| m.id())),
        credential_blob_id: Set(credential_blob_id),
        wallet_unit_attestation_blob_id: Set(wallet_unit_attestation_blob_id),
        wallet_instance_attestation_blob_id: Set(wallet_instance_attestation_blob_id),
        webhook_url: Set(request.webhook_url.to_owned()),
        embedded_disclosure_policy: Set(request.embedded_disclosure_policy.clone()),
        subscriber_information: Set(request.subscriber_information.clone()),
        ecosystem: Set(request.ecosystem.clone()),
        r#type: Set(request.r#type.into()),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn credential_list_model_to_repository_model(
    credential: CredentialListEntityModel,
    credential_repository: &Arc<dyn CredentialRepository>,
    claim_repository: &Arc<dyn ClaimRepository>,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    did_repository: &Arc<dyn DidRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    trust_information_repository: &Arc<dyn IdentifierTrustInformationRepository>,
    db: &TransactionManagerImpl,
) -> Result<Credential, DataLayerError> {
    let transaction_code = match (
        credential.credential_schema_transaction_code_type,
        credential.credential_schema_transaction_code_length,
    ) {
        (Some(r#type), Some(length)) => Some(TransactionCode {
            r#type: r#type.into(),
            length: length as _,
            description: credential.credential_schema_transaction_code_description,
        }),
        (None, None) => None,
        _ => return Err(DataLayerError::MappingError),
    };

    let formats = RelatedVec::new(CredentialSchemaFormatsLoader {
        id: credential.credential_schema_id,
        db: db.clone(),
    });
    let schema = CredentialSchema {
        id: credential.credential_schema_id,
        ecosystem: credential.credential_schema_ecosystem,
        deleted_at: credential.credential_schema_deleted_at,
        created_date: credential.credential_schema_created_date,
        last_modified: credential.credential_schema_last_modified,
        key_storage_security: convert_inner(credential.credential_schema_key_storage_security),
        name: credential.credential_schema_name,
        formats,
        imported_source_url: credential.credential_schema_imported_source_url,
        claim_schemas: RelatedVec::new(ClaimSchemasLoader {
            id: credential.credential_schema_id,
            db: db.to_owned(),
        }),
        organisation: Related::new(
            credential.credential_schema_organisation_id,
            organisation_repository.to_owned(),
        ),
        // todo: this should be fixed in another ticket
        layout_type: LayoutType::Card,
        layout_properties: credential
            .credential_schema_schema_layout_properties
            .map(|layout_properties| layout_properties.into()),
        allow_suspension: credential.credential_schema_allow_suspension,
        requires_wallet_instance_attestation: credential
            .credential_schema_requires_wallet_instance_attestation,
        transaction_code,
        batch_size: credential.credential_schema_batch_size,
        allow_revocation: credential.credential_schema_allow_revocation,
        embedded_disclosure_policy: credential.credential_schema_embedded_disclosure_policy,
        expiration: credential
            .credential_schema_expiration
            .map(|seconds| Duration::seconds(seconds as i64)),
        translations: RelatedVec::new(LocalizedTextLoader {
            id: credential.credential_schema_id.into(),
            db: db.to_owned(),
        }),
    };

    let issuer_identifier = match credential.issuer_identifier_id {
        None => None,
        Some(issuer_identifier_id) => Some(
            Identifier {
                id: issuer_identifier_id,
                created_date: credential
                    .issuer_identifier_created_date
                    .ok_or(DataLayerError::MappingError)?,
                last_modified: credential
                    .issuer_identifier_last_modified
                    .ok_or(DataLayerError::MappingError)?,
                name: credential
                    .issuer_identifier_name
                    .ok_or(DataLayerError::MappingError)?,
                data: identifier_data_from_ids(
                    credential
                        .issuer_identifier_type
                        .ok_or(DataLayerError::MappingError)?
                        .into(),
                    issuer_identifier_id,
                    credential.issuer_identifier_did_id,
                    credential.issuer_identifier_key_id,
                    did_repository,
                    key_repository,
                    certificate_repository,
                )?,
                organisation: Related::new(
                    credential
                        .issuer_identifier_organisation_id
                        .ok_or(DataLayerError::MappingError)?,
                    organisation_repository.to_owned(),
                ),
                is_remote: credential
                    .issuer_identifier_is_remote
                    .ok_or(DataLayerError::MappingError)?,
                state: credential
                    .issuer_identifier_state
                    .ok_or(DataLayerError::MappingError)?
                    .into(),
                deleted_at: None,
                trust_information: identifier_trust_information(
                    issuer_identifier_id,
                    trust_information_repository,
                ),
            }
            .into(),
        ),
    };

    Ok(Credential {
        id: credential.id,
        created_date: credential.created_date,
        issuance_date: credential.issuance_date,
        expires_at: credential.expires_at,
        last_modified: credential.last_modified,
        deleted_at: credential.deleted_at,
        consumed_at: credential.consumed_at,
        protocol: credential.protocol,
        redirect_uri: credential.redirect_uri,
        role: credential.role.into(),
        r#type: credential.r#type.into(),
        state: credential.state.into(),
        suspend_end_date: credential.suspend_end_date,
        profile: credential.profile,
        claims: credential_claims(credential.id, claim_repository),
        issuer_identifier,
        issuer_certificate: credential
            .issuer_certificate_id
            .map(|id| Related::new(id, certificate_repository.to_owned())),
        holder_identifier: credential
            .holder_identifier_id
            .map(|id| Related::new(id, identifier_repository.to_owned())),
        schema: Related::from(schema),
        interaction: credential
            .interaction_id
            .map(|id| Related::new(id, interaction_repository.to_owned())),
        key: credential
            .key_id
            .map(|id| Related::new(id, key_repository.to_owned())),
        credential_blob_id: credential.credential_blob_id,
        wallet_unit_attestation_blob_id: credential.wallet_unit_attestation_blob_id,
        wallet_instance_attestation_blob_id: credential.wallet_instance_attestation_blob_id,
        webhook_url: credential.webhook_url,
        embedded_disclosure_policy: credential.embedded_disclosure_policy,
        subscriber_information: credential.subscriber_information,
        ecosystem: credential.ecosystem,
        parent: credential
            .parent_id
            .map(|id| Related::new(id, credential_repository.clone())),
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn credentials_to_repository(
    credentials: Vec<CredentialListEntityModel>,
    credential_repository: &Arc<dyn CredentialRepository>,
    claim_repository: &Arc<dyn ClaimRepository>,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    did_repository: &Arc<dyn DidRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    interaction_repository: &Arc<dyn InteractionRepository>,
    trust_information_repository: &Arc<dyn IdentifierTrustInformationRepository>,
    db: &TransactionManagerImpl,
) -> Result<Vec<Credential>, DataLayerError> {
    let mut result: Vec<Credential> = Vec::new();
    for credential in credentials.into_iter() {
        result.push(credential_list_model_to_repository_model(
            credential,
            credential_repository,
            claim_repository,
            organisation_repository,
            did_repository,
            key_repository,
            certificate_repository,
            identifier_repository,
            interaction_repository,
            trust_information_repository,
            db,
        )?);
    }

    Ok(result)
}
