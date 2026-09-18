use one_dto_mapper::convert_inner;

use crate::model::history::{
    GetIssuerStats, GetSystemInteractionStats, GetSystemManagementStats, GetVerifierStats,
    SystemOrgStats,
};
use crate::service::statistics::dto::{
    GetIssuerStatsResponseDTO, GetSystemInteractionStatsResponseDTO,
    GetSystemManagementStatsResponseDTO, GetVerifierStatsResponseDTO, SystemOrgStatsResponseDTO,
};

impl From<GetIssuerStats<u64>> for GetIssuerStatsResponseDTO {
    fn from(value: GetIssuerStats<u64>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<GetVerifierStats<u64>> for GetVerifierStatsResponseDTO {
    fn from(value: GetVerifierStats<u64>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<GetSystemInteractionStats<u64>> for GetSystemInteractionStatsResponseDTO {
    fn from(value: GetSystemInteractionStats<u64>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl From<GetSystemManagementStats<u64>> for GetSystemManagementStatsResponseDTO {
    fn from(value: GetSystemManagementStats<u64>) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

impl<IN, OUT: From<IN>> From<SystemOrgStats<IN>> for SystemOrgStatsResponseDTO<OUT> {
    fn from(value: SystemOrgStats<IN>) -> Self {
        Self {
            organisation_id: value.organisation_id,
            current: value.current.into(),
            previous: convert_inner(value.previous),
        }
    }
}
