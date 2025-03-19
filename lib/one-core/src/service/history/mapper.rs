use one_dto_mapper::convert_inner;

use crate::model::history::GetHistoryList;
use crate::service::history::dto::GetHistoryListResponseDTO;

impl From<GetHistoryList> for GetHistoryListResponseDTO {
    fn from(value: GetHistoryList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}
