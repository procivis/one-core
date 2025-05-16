use one_core::model::certificate::CertificateState;
use one_core::service::certificate::dto::{
    CertificateResponseDTO, CertificateX509AttributesDTO, CertificateX509ExtensionDTO,
};
use one_dto_mapper::{From, Into, TryFrom, convert_inner, try_convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CertificateId, OrganisationId};
use time::OffsetDateTime;
use utoipa::ToSchema;

use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[serde(rename_all = "camelCase")]
#[try_from(T = CertificateResponseDTO, Error = MapperError)]
pub struct CertificateResponseRestDTO {
    #[try_from(infallible)]
    pub id: CertificateId,
    #[try_from(infallible)]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    pub chain: String,
    #[try_from(infallible)]
    pub state: CertificateStateRest,
    #[try_from(with_fn = "try_convert_inner")]
    pub key: Option<KeyListItemResponseRestDTO>,
    #[try_from(infallible)]
    pub x509_attributes: CertificateX509AttributesRestDTO,
    #[try_from(infallible)]
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(CertificateState)]
#[into(CertificateState)]
pub enum CertificateStateRest {
    NotYetActive,
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CertificateX509AttributesDTO)]
pub struct CertificateX509AttributesRestDTO {
    pub serial_number: String,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub not_before: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub not_after: OffsetDateTime,
    pub issuer: String,
    pub subject: String,
    pub fingerprint: String,
    #[from(with_fn = convert_inner)]
    pub extensions: Vec<CertificateX509ExtensionRestDTO>,
}

#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CertificateX509ExtensionDTO)]
pub struct CertificateX509ExtensionRestDTO {
    pub oid: String,
    pub value: String,
    pub critical: bool,
}
