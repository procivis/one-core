use shared_types::DidId;
use std::sync::Arc;

use one_core::{
    model::did::{Did, DidRelations},
    repository::{did_repository::DidRepository, error::DataLayerError},
};

pub(super) fn calculate_pages_count(total_items_count: u64, page_size: u64) -> u64 {
    if page_size == 0 {
        return 0;
    }

    (total_items_count / page_size) + std::cmp::min(total_items_count % page_size, 1)
}

pub(crate) async fn get_did(
    did_id: &DidId,
    relations: &Option<DidRelations>,
    repository: Arc<dyn DidRepository + Send + Sync>,
) -> Result<Option<Did>, DataLayerError> {
    match relations {
        None => Ok(None),
        Some(did_relations) => Ok(Some(repository.get_did(did_id, did_relations).await?)),
    }
}

#[cfg(test)]
mod tests {
    use super::calculate_pages_count;

    #[test]
    fn test_calculate_pages_count() {
        assert_eq!(0, calculate_pages_count(1, 0));

        assert_eq!(1, calculate_pages_count(1, 1));
        assert_eq!(1, calculate_pages_count(1, 2));
        assert_eq!(1, calculate_pages_count(1, 100));

        assert_eq!(5, calculate_pages_count(50, 10));
        assert_eq!(6, calculate_pages_count(51, 10));
        assert_eq!(6, calculate_pages_count(52, 10));
        assert_eq!(6, calculate_pages_count(60, 10));
        assert_eq!(7, calculate_pages_count(61, 10));
    }
}
