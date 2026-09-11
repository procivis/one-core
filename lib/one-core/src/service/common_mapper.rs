use ct_codecs::{Base64, Decoder};
use shared_types::EntityId;

use crate::error::{ContextWithErrorCode, NestedError};
use crate::model::common::SortDirection;
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::history::{
    HistoryAction, HistoryFilterValue, HistoryMetadata, SortableHistoryColumn,
};
use crate::model::list_filter::{ListFilterCondition, ListFilterValue};
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::provider::ecosystem::model::TrustDetailInfo;
use crate::repository::history_repository::HistoryRepository;
use crate::service::common_dto::{
    BoundedB64Image, ListQueryDTO, TrustInformationDetailResponseEnum,
};
use crate::service::error::ValidationError;

/// The interaction is long gone by the time an entity's detail is read, so the recorded event
/// is the only place this survives. Empty when no ecosystem was ever consulted.
pub(crate) async fn recorded_ecosystem_outcomes(
    entity_id: EntityId,
    history_repository: &dyn HistoryRepository,
) -> Result<EcosystemOutcomes, NestedError> {
    let history = history_repository
        .get_history_list(ListQuery {
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
    use ct_codecs::{Base64, Encoder};

    use super::BoundedB64Image;
    use crate::service::error::ValidationError;

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
