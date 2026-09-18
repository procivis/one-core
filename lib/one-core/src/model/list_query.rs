use super::common::SortDirection;
use super::list_filter::ListFilterCondition;

#[derive(Clone, Debug, Default)]
pub struct NoInclude {}

#[derive(Clone, Debug)]
pub struct ListQuery<SortableColumn, FV, Include = NoInclude> {
    /// Include total items and pages (enabled by default). When false, both totals are absent.
    pub include_count: bool,
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

impl<SortableColumn, FV, Include> Default for ListQuery<SortableColumn, FV, Include> {
    fn default() -> Self {
        Self {
            include_count: true,
            pagination: Default::default(),
            sorting: Default::default(),
            filtering: Default::default(),
            include: Default::default(),
        }
    }
}
