use crate::repository::error::DataLayerError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Clone, Debug)]
pub struct GetListResponse<ResponseItem, Count = u64> {
    pub values: Vec<ResponseItem>,
    pub total_pages: Count,
    pub total_items: Count,
}

impl<ResponseItem> GetListResponse<ResponseItem, Option<u64>> {
    pub fn require_count(self) -> Result<GetListResponse<ResponseItem>, DataLayerError> {
        Ok(GetListResponse {
            values: self.values,
            total_pages: self.total_pages.ok_or(DataLayerError::MissingCount)?,
            total_items: self.total_items.ok_or(DataLayerError::MissingCount)?,
        })
    }
}

#[cfg(test)]
impl<ResponseItem, Count: From<u64>> GetListResponse<ResponseItem, Count> {
    pub fn empty() -> Self {
        Self {
            values: vec![],
            total_pages: 0.into(),
            total_items: 0.into(),
        }
    }

    pub fn one(value: ResponseItem) -> Self {
        Self {
            values: vec![value],
            total_pages: 1.into(),
            total_items: 1.into(),
        }
    }

    pub fn one_page_of(values: Vec<ResponseItem>) -> Self {
        let total_items = values.len() as u64;
        Self {
            values,
            total_pages: 1.into(),
            total_items: total_items.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockType {
    /// Exclusive lock
    Update,
    /// Shared lock
    Share,
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn require_count_preserves_values_and_totals() {
        for (total_items, total_pages) in [(0, 0), (7, 4)] {
            let result = GetListResponse {
                values: vec!["item"],
                total_items: Some(total_items),
                total_pages: Some(total_pages),
            }
            .require_count()
            .unwrap();
            assert_eq!(result.values, ["item"]);
            assert_eq!(result.total_items, total_items);
            assert_eq!(result.total_pages, total_pages);
        }
    }

    #[test]
    fn require_count_rejects_either_missing_total() {
        for (total_items, total_pages) in [(None, None), (Some(0), None), (None, Some(0))] {
            let result = GetListResponse::<(), Option<u64>> {
                values: vec![],
                total_items,
                total_pages,
            };
            assert!(matches!(
                result.require_count(),
                Err(DataLayerError::MissingCount)
            ));
        }
    }
}
