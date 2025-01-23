use one_dto_mapper::Into;

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(one_core::model::common::SortDirection)]
pub enum SortDirection {
    Ascending,
    Descending,
}
