use ct_codecs::{Base64, Decoder};
use shared_types::{EntityId, InteractionId, OrganisationId};
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::common::SortDirection;
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::{
    History, HistoryAction, HistoryEntityType, HistoryFilterValue, HistoryMetadata, HistorySource,
    SortableHistoryColumn,
};
use crate::model::list_filter::{ListFilterCondition, ListFilterValue};
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::provider::ecosystem::model::TrustDetailInfo;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::service::common_dto::{
    BoundedB64Image, ListQueryDTO, TrustInformationDetailResponseEnum,
};
use crate::service::error::ValidationError;

/// `None` when no ecosystem was ever consulted. Best-effort like the writer it feeds: the
/// flow has already ended, so an interaction that cannot be loaded is only logged.
pub(crate) async fn resolved_ecosystems(
    interaction_id: &InteractionId,
    interaction_repository: &dyn InteractionRepository,
) -> Option<(EcosystemOutcomes, OrganisationId)> {
    let interaction = match interaction_repository
        .get_interaction(interaction_id, None)
        .await
    {
        Ok(interaction) => interaction,
        Err(err) => {
            tracing::warn!(%err, "failed to load interaction {interaction_id} to record the resolved ecosystems");
            return None;
        }
    };

    let outcomes = interaction.ecosystem_data.outcomes();
    if outcomes.is_empty() {
        return None;
    }

    Some((outcomes.to_owned(), interaction.organisation.id()))
}

/// One event per entity the interaction produced. Best-effort: the interaction has already
/// ended, so a failed write must not change its result.
pub(crate) async fn record_ecosystems_resolved(
    outcomes: &EcosystemOutcomes,
    organisation_id: OrganisationId,
    entities: &[(EntityId, HistoryEntityType)],
    user: Option<String>,
    history_repository: &dyn HistoryRepository,
) {
    if outcomes.is_empty() {
        return;
    }

    for (entity_id, entity_type) in entities {
        let result = history_repository
            .create_history(History {
                id: Uuid::new_v4().into(),
                created_date: crate::clock::now_utc(),
                action: HistoryAction::EcosystemsResolved,
                name: Default::default(),
                target: None,
                source: HistorySource::Core,
                entity_id: Some(*entity_id),
                entity_type: entity_type.to_owned(),
                metadata: Some(HistoryMetadata::EcosystemsResolved(outcomes.to_owned())),
                organisation_id: Some(organisation_id),
                user: user.to_owned(),
                metadata_blob_id: None,
            })
            .await;

        if let Err(err) = result {
            tracing::warn!(%err, "failed to record the resolved ecosystems");
        }
    }
}

/// The interaction is long gone by the time an entity's detail is read, so the recorded event
/// is the only place this survives. Empty when no ecosystem was ever consulted.
pub(crate) async fn recorded_ecosystem_outcomes(
    entity_id: EntityId,
    history_repository: &dyn HistoryRepository,
) -> Result<EcosystemOutcomes, NestedError> {
    let history = history_repository
        .get_history_list(ListQuery {
            include_count: false,
            filtering: Some(
                HistoryFilterValue::EntityIds(vec![entity_id]).condition()
                    & HistoryFilterValue::Actions(vec![HistoryAction::EcosystemsResolved]),
            ),
            sorting: Some(ListSorting {
                column: SortableHistoryColumn::CreatedDate,
                direction: Some(SortDirection::Descending),
            }),
            // only the newest event is read, so the query must not load the entity's whole history
            pagination: Some(ListPagination {
                page: 0,
                page_size: 1,
            }),
            ..Default::default()
        })
        .await
        .error_while("getting the resolved ecosystems")?;

    Ok(history
        .values
        .into_iter()
        .find_map(|entry| match entry.metadata {
            Some(HistoryMetadata::EcosystemsResolved(outcomes)) => Some(outcomes),
            _ => None,
        })
        .unwrap_or_default())
}

impl<const MAX: usize> TryFrom<String> for BoundedB64Image<MAX> {
    type Error = ValidationError;

    fn try_from(img: String) -> Result<Self, Self::Error> {
        let mut splits = img.splitn(2, ',');
        match splits.next() {
            Some("data:image/png;base64") | Some("data:image/jpeg;base64") => {}
            Some(data) => {
                return Err(ValidationError::InvalidImage(format!(
                    "Invalid mime type: {data}"
                )));
            }
            None => {
                return Err(ValidationError::InvalidImage(
                    "Missing mime type".to_owned(),
                ));
            }
        };
        let Some(base64) = splits.next() else {
            return Err(ValidationError::InvalidImage(
                "Missing base64 data".to_string(),
            ));
        };
        let mut buf = vec![0; MAX];
        // Decode will fail if data is longer than `buf` (`MAX` bytes)
        Base64::decode(buf.as_mut_slice(), base64, None).map_err(|err| {
            ValidationError::InvalidImage(format!("Failed to decode base64 data: {err}"))
        })?;
        Ok(BoundedB64Image(img))
    }
}
impl<const MAX: usize> From<BoundedB64Image<MAX>> for String {
    fn from(value: BoundedB64Image<MAX>) -> Self {
        value.0
    }
}

impl<const MAX: usize> BoundedB64Image<MAX> {
    pub fn max_size() -> usize {
        MAX
    }
}

impl<Sorting, FilterDTO, Filter, Include> From<ListQueryDTO<Sorting, FilterDTO, Include>>
    for ListQuery<Sorting, Filter, Include>
where
    FilterDTO: Into<ListFilterCondition<Filter>>,
{
    fn from(value: ListQueryDTO<Sorting, FilterDTO, Include>) -> Self {
        Self {
            include_count: true,
            pagination: Some(ListPagination {
                page: value.page,
                page_size: value.page_size,
            }),
            sorting: value.sort.map(|column| ListSorting {
                column,
                direction: value.sort_direction,
            }),
            filtering: Some(value.filter.into()),
            include: value.include,
        }
    }
}

impl From<TrustDetailInfo> for TrustInformationDetailResponseEnum {
    fn from(value: TrustDetailInfo) -> Self {
        match value {
            TrustDetailInfo::Eudi(detail) => Self::Eudi(detail),
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use ct_codecs::{Base64, Encoder};
    use shared_types::EcosystemId;
    use similar_asserts::assert_eq;
    use uuid::Uuid;

    use super::*;
    use crate::error::ErrorCode;
    use crate::model::common::GetListResponse;
    use crate::model::history::HistoryErrorMetadata;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::service::error::ValidationError;

    fn outcomes(entries: &[(&str, Result<(), HistoryErrorMetadata>)]) -> EcosystemOutcomes {
        let mut outcomes = EcosystemOutcomes::default();
        for (ecosystem, outcome) in entries {
            outcomes.record(EcosystemId::from(*ecosystem), outcome.to_owned());
        }
        outcomes
    }

    fn rejected(message: &str) -> Result<(), HistoryErrorMetadata> {
        Err(HistoryErrorMetadata {
            error_code: ErrorCode::BR_0477,
            message: message.to_string(),
        })
    }

    /// A history repository recording every event written to it.
    fn recording_repository() -> (MockHistoryRepository, Arc<Mutex<Vec<History>>>) {
        let written = Arc::new(Mutex::new(vec![]));
        let captured = written.to_owned();

        let mut history_repository = MockHistoryRepository::new();
        history_repository
            .expect_create_history()
            .returning(move |history| {
                let id = history.id;
                captured.lock().unwrap().push(history);
                Ok(id)
            });

        (history_repository, written)
    }

    #[tokio::test]
    async fn test_one_event_is_written_per_entity_the_interaction_produced() {
        let (history_repository, written) = recording_repository();
        let organisation_id = Uuid::new_v4().into();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let recorded = outcomes(&[("EUDI", Ok(())), ("OTHER", rejected("not on the list"))]);

        record_ecosystems_resolved(
            &recorded,
            organisation_id,
            &[
                (first.into(), HistoryEntityType::Credential),
                (second.into(), HistoryEntityType::Credential),
            ],
            Some("user".to_string()),
            &history_repository,
        )
        .await;

        let written = written.lock().unwrap();
        assert_eq!(2, written.len());
        for (entity, event) in [first, second].iter().zip(written.iter()) {
            assert_eq!(HistoryAction::EcosystemsResolved, event.action);
            assert_eq!(HistoryEntityType::Credential, event.entity_type);
            assert_eq!(Some(EntityId::from(*entity)), event.entity_id);
            assert_eq!(Some(organisation_id), event.organisation_id);
            assert_eq!(Some("user".to_string()), event.user);

            let Some(HistoryMetadata::EcosystemsResolved(carried)) = &event.metadata else {
                panic!("the event carries the recorded outcomes");
            };
            assert_eq!(&recorded, carried);
        }
    }

    #[tokio::test]
    async fn test_nothing_is_written_when_no_ecosystem_was_consulted() {
        let mut history_repository = MockHistoryRepository::new();
        history_repository.expect_create_history().never();

        record_ecosystems_resolved(
            &EcosystemOutcomes::default(),
            Uuid::new_v4().into(),
            &[(Uuid::new_v4().into(), HistoryEntityType::Credential)],
            None,
            &history_repository,
        )
        .await;
    }

    #[tokio::test]
    async fn test_the_newest_recorded_outcomes_are_read_back() {
        let entity_id = EntityId::from(Uuid::new_v4());
        let newest = outcomes(&[("EUDI", rejected("newest"))]);
        let returned = newest.to_owned();

        let mut history_repository = MockHistoryRepository::new();
        history_repository
            .expect_get_history_list()
            .withf(|query| {
                // only the newest event, and only that one
                let sorting = query.sorting.as_ref().expect("sorted by recency");
                let pagination = query.pagination.as_ref().expect("limited to one event");
                matches!(sorting.column, SortableHistoryColumn::CreatedDate)
                    && sorting.direction == Some(SortDirection::Descending)
                    && pagination.page_size == 1
            })
            .returning(move |_| {
                Ok(GetListResponse {
                    values: vec![History {
                        id: Uuid::new_v4().into(),
                        created_date: crate::clock::now_utc(),
                        action: HistoryAction::EcosystemsResolved,
                        name: Default::default(),
                        target: None,
                        source: HistorySource::Core,
                        entity_id: Some(entity_id),
                        entity_type: HistoryEntityType::Credential,
                        metadata: Some(HistoryMetadata::EcosystemsResolved(returned.to_owned())),
                        organisation_id: None,
                        user: None,
                        metadata_blob_id: None,
                    }],
                    total_pages: Some(1),
                    total_items: Some(1),
                })
            });

        assert_eq!(
            newest,
            recorded_ecosystem_outcomes(entity_id, &history_repository)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_an_entity_with_no_recorded_event_reads_back_empty() {
        let mut history_repository = MockHistoryRepository::new();
        history_repository.expect_get_history_list().returning(|_| {
            Ok(GetListResponse {
                values: vec![],
                total_pages: Some(0),
                total_items: Some(0),
            })
        });

        assert!(
            recorded_ecosystem_outcomes(EntityId::from(Uuid::new_v4()), &history_repository)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn test_bounded_base64_image() {
        let data = vec![0; 10];
        let data_str = format!(
            "data:image/png;base64,{}",
            Base64::encode_to_string(&data).unwrap()
        );
        let result = BoundedB64Image::<10>::try_from(data_str.clone());
        assert!(result.is_ok());

        let result = BoundedB64Image::<9>::try_from(data_str);
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));

        let result =
            BoundedB64Image::<10>::try_from("data:image/png;base64,NÖT_BÄSE64".to_string());
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));

        let result = BoundedB64Image::<10>::try_from(format!(
            "data:image/gif;base64,{}", // unsupported mime type
            Base64::encode_to_string(&data).unwrap()
        ));
        assert!(matches!(result, Err(ValidationError::InvalidImage(_))));
    }
}
