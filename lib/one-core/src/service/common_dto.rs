use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::EcosystemId;
use standardized_types::etsi_119_475::registration_certificate::SupervisoryAuthority;
use url::Url;

use crate::model::common::SortDirection;
use crate::model::list_query::NoInclude;

pub const KB: usize = 1 << 10;
pub const MB: usize = KB << 10;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BoundedB64Image<const MAX: usize>(pub(crate) String);

#[derive(Clone, Debug)]
pub struct ListQueryDTO<SortColumn, Filter, Include = NoInclude> {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortColumn>,
    pub sort_direction: Option<SortDirection>,

    pub filter: Filter,
    pub include: Option<Vec<Include>>,
}

#[derive(Clone, Debug, Default)]
pub struct TrustInformationDetailResponseDTO {
    pub eudi_ecosystem: Option<EudiTrustInformationResponseDTO>,

    pub ecosystem: Option<EcosystemId>,
    pub issuer: Option<TrustInformationDetailResponseEnum>,
    pub verifier: Option<TrustInformationDetailResponseEnum>,
}

#[derive(Clone, Debug)]
pub enum TrustInformationDetailResponseEnum {
    Eudi(EudiTrustInformationResponseDTO),
}

#[derive(Clone, Debug)]
pub struct EudiTrustInformationResponseDTO {
    pub name: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
    pub identifier: String,
    pub service_description: Vec<HashMap<String, String>>,
    pub supervisory_authority: SupervisoryAuthority,
    pub intermediary: Option<EudiIntermediaryResponseDTO>,
    pub is_public_sector: bool,
}

#[derive(Clone, Debug)]
pub struct EudiIntermediaryResponseDTO {
    pub name: Option<String>,
    pub identifier: String,
    pub website: Url,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub country: String,
}
