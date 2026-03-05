use one_dto_mapper::convert_inner;

use crate::model::history::{GetIssuerStats, GetSystemInteractionStats, GetVerifierStats};
use crate::service::statistics::dto::{
    GetIssuerStatsResponseDTO, GetSystemInteractionStatsResponseDTO, GetVerifierStatsResponseDTO,
};

impl From<GetIssuerStats> for GetIssuerStatsResponseDTO {
    fn from(value: GetIssuerStats) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<GetVerifierStats> for GetVerifierStatsResponseDTO {
    fn from(value: GetVerifierStats) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<GetSystemInteractionStats> for GetSystemInteractionStatsResponseDTO {
    fn from(value: GetSystemInteractionStats) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}
