use super::{common::SortDirection, list_filter::ListFilterCondition};

#[derive(Clone, Debug)]
pub struct ListQuery<SortableColumn, FilterValue> {
    pub pagination: Option<ListPagination>,
    pub sorting: Option<ListSorting<SortableColumn>>,
    pub filtering: Option<ListFilterCondition<FilterValue>>,
}

#[derive(Clone, Debug)]
pub struct ListPagination {
    pub page: u32,
    pub page_size: u32,
}

#[derive(Clone, Debug)]
pub struct ListSorting<SortableColumn> {
    pub column: SortableColumn,
    pub direction: Option<SortDirection>,
}

impl<SortableColumn, FilterValue> Default for ListQuery<SortableColumn, FilterValue> {
    fn default() -> Self {
        Self {
            pagination: Default::default(),
            sorting: Default::default(),
            filtering: Default::default(),
        }
    }
}
