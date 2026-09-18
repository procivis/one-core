use one_dto_mapper::convert_inner;
use uuid::Uuid;

use crate::model::history::{
    GetHistoryList, History, HistoryFilterValue, HistoryMetadata, HistorySearchEnum,
};
use crate::model::list_filter::{ComparisonType, ListFilterCondition, ValueComparison};
use crate::service::history::dto::{
    CreateHistoryRequestDTO, GetHistoryListResponseDTO, HistoryFilterParamsDTO,
};

impl From<GetHistoryList<u64>> for GetHistoryListResponseDTO {
    fn from(value: GetHistoryList<u64>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<CreateHistoryRequestDTO> for History {
    fn from(value: CreateHistoryRequestDTO) -> Self {
        Self {
            id: Uuid::new_v4().into(),
            created_date: crate::clock::now_utc(),
            action: value.action,
            name: value.name,
            target: value.target,
            source: value.source,
            entity_id: value.entity_id,
            entity_type: value.entity_type,
            metadata: value.metadata.map(HistoryMetadata::External),
            organisation_id: value.organisation_id,
            user: None,
            metadata_blob_id: None,
        }
    }
}

impl From<HistoryFilterParamsDTO> for ListFilterCondition<HistoryFilterValue> {
    fn from(filter: HistoryFilterParamsDTO) -> Self {
        let organisation_ids = filter
            .organisation_ids
            .map(HistoryFilterValue::OrganisationIds);
        let entity_ids = filter.entity_ids.map(HistoryFilterValue::EntityIds);
        let entity_types = filter.entity_types.map(HistoryFilterValue::EntityTypes);
        let actions = filter.actions.map(HistoryFilterValue::Actions);
        let identifier_id = filter.identifier_id.map(HistoryFilterValue::IdentifierId);

        let created_date_after = filter.created_date_after.map(|date| {
            HistoryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = filter.created_date_before.map(|date| {
            HistoryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let credential_id = filter.credential_id.map(HistoryFilterValue::CredentialId);
        let credential_schema_id = filter
            .credential_schema_id
            .map(HistoryFilterValue::CredentialSchemaId);
        let proof_id = filter.proof_id.map(HistoryFilterValue::ProofId);
        let proof_schema_id = filter
            .proof_schema_id
            .map(HistoryFilterValue::ProofSchemaId);
        let trust_collection_id = filter
            .trust_collection_id
            .map(HistoryFilterValue::TrustCollectionId);
        let users = filter.users.map(HistoryFilterValue::Users);
        let sources = filter.sources.map(HistoryFilterValue::Sources);

        let search_query = filter.search_query.map(|query| {
            let search_type = filter.search_type.unwrap_or(HistorySearchEnum::All);
            HistoryFilterValue::SearchQuery(query, search_type)
        });

        ListFilterCondition::<HistoryFilterValue>::default()
            & organisation_ids
            & entity_ids
            & entity_types
            & actions
            & identifier_id
            & created_date_after
            & created_date_before
            & credential_id
            & credential_schema_id
            & proof_id
            & proof_schema_id
            & trust_collection_id
            & users
            & sources
            & search_query
    }
}
