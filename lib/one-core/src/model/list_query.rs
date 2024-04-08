use super::{
    common::SortDirection,
    list_filter::{ListFilterCondition, ListFilterValue},
};

#[derive(Clone, Debug)]
pub struct ListQuery<SortableColumn, FV: ListFilterValue, Include> {
    pub pagination: Option<ListPagination>,
    pub sorting: Option<ListSorting<SortableColumn>>,
    pub filtering: Option<ListFilterCondition<FV>>,
    pub include: Option<Vec<Include>>,
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

impl<SortableColumn, FV: ListFilterValue, Include> Default
    for ListQuery<SortableColumn, FV, Include>
{
    fn default() -> Self {
        Self {
            pagination: Default::default(),
            sorting: Default::default(),
            filtering: Default::default(),
            include: Default::default(),
        }
    }
}
