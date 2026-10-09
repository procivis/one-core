use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::relation::Related;
use one_core::model::trust_list_publication::{
    SortableTrustListPublicationColumn, TrustListPublication, TrustListPublicationFilterValue,
};
use one_core::repository::certificate_repository::CertificateRepository;
use one_core::repository::identifier_repository::IdentifierRepository;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::ActiveValue::Set;
use sea_orm::ColumnTrait;
use sea_orm::sea_query::{ColumnRef, IntoCondition, Query};

use crate::entity::trust_list_publication::TrustRoleEnum;
use crate::entity::{trust_entry, trust_list_publication};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoSortingColumn, get_comparison_condition,
    get_equals_condition, get_string_match_condition,
};

pub(crate) fn trust_list_publication_from_model(
    value: trust_list_publication::Model,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    identifier_repository: &Arc<dyn IdentifierRepository>,
    key_repository: &Arc<dyn KeyRepository>,
    certificate_repository: &Arc<dyn CertificateRepository>,
) -> TrustListPublication {
    TrustListPublication {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        role: value.role.into(),
        r#type: value.r#type,
        metadata: value.metadata,
        deleted_at: value.deleted_at,
        content: value.content,
        sequence_number: value.sequence_number as u32,
        organisation: Related::new(value.organisation_id, organisation_repository.clone()),
        identifier: Related::new(value.identifier_id, identifier_repository.clone()),
        key: value
            .key_id
            .map(|key_id| Related::new(key_id, key_repository.clone())),
        certificate: value
            .certificate_id
            .map(|certificate_id| Related::new(certificate_id, certificate_repository.clone())),
    }
}

impl From<TrustListPublication> for trust_list_publication::ActiveModel {
    fn from(value: TrustListPublication) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            role: Set(value.role.into()),
            r#type: Set(value.r#type),
            metadata: Set(value.metadata),
            deleted_at: Set(value.deleted_at),
            content: Set(value.content),
            sequence_number: Set(value.sequence_number as i32),
            organisation_id: Set(value.organisation.id()),
            identifier_id: Set(value.identifier.id()),
            key_id: Set(value.key.map(|key| key.id())),
            certificate_id: Set(value.certificate.map(|certificate| certificate.id())),
        }
    }
}

impl IntoSortingColumn for SortableTrustListPublicationColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Role => ColumnSortingBehavior::default(trust_list_publication::Column::Role),
            Self::Type => ColumnSortingBehavior::default(trust_list_publication::Column::Type),
            Self::Name => {
                ColumnSortingBehavior::case_insensitive(trust_list_publication::Column::Name)
            }
            Self::CreatedDate => {
                ColumnSortingBehavior::default(trust_list_publication::Column::CreatedDate)
            }
            Self::LastModified => {
                ColumnSortingBehavior::default(trust_list_publication::Column::LastModified)
            }
        }
    }
}

impl IntoFilterCondition for TrustListPublicationFilterValue {
    fn get_condition(
        self,
        _entire_filter: &ListFilterCondition<TrustListPublicationFilterValue>,
    ) -> sea_orm::Condition {
        match self {
            Self::OrganisationId(id) => {
                get_equals_condition(trust_list_publication::Column::OrganisationId, id)
            }
            Self::TrustEntryIdentifierId(id) => trust_list_publication::Column::Id
                .in_subquery(
                    Query::select()
                        .column(trust_entry::Column::TrustListPublicationId)
                        .from(trust_entry::Entity)
                        .and_where(trust_entry::Column::IdentifierId.eq(id))
                        .to_owned(),
                )
                .into_condition(),
            Self::Name(string_match) => {
                get_string_match_condition(trust_list_publication::Column::Name, string_match)
            }
            Self::Type(types) => trust_list_publication::Column::Type
                .is_in(types)
                .into_condition(),
            Self::Role(roles) => {
                let roles = roles
                    .into_iter()
                    .map(TrustRoleEnum::from)
                    .collect::<Vec<_>>();
                trust_list_publication::Column::Role
                    .is_in(roles)
                    .into_condition()
            }
            Self::CreatedDate(value) => {
                get_comparison_condition(trust_list_publication::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(trust_list_publication::Column::LastModified, value)
            }
            Self::Ids(value) => trust_list_publication::Column::Id
                .is_in(value)
                .into_condition(),
        }
    }
}
