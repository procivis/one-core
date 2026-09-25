//! ETSI TS 119 602 — List of Trusted Entities (LoTE)
//!
//! XML binding types for the LoTE trust list format (Annex A.2.1).

use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
mod mapper;
mod serde_wrappers;

use crate::etsi_119_602::json::{LoTEType, ServiceStatus};

pub const LOTE_NS: &str = "http://uri.etsi.org/019602/v1#";
pub const LOTE_TAG: &str = "http://uri.etsi.org/019602/tag#";

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename = "ListOfTrustedEntities", rename_all = "PascalCase")]
pub struct LoTEPayload {
    #[serde(rename = "@xmlns")]
    pub xmlns: String,

    #[serde(rename = "@LOTETag", default)]
    pub lote_tag: String,

    pub list_and_scheme_information: ListAndSchemeInformation,
    pub trusted_entities_list: Option<TrustedEntitiesList>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::ListAndSchemeInformation)]
#[into(super::json::ListAndSchemeInformation)]
pub struct ListAndSchemeInformation {
    #[serde(rename = "LoTEVersionIdentifier")]
    pub lote_version_identifier: u64,

    #[serde(rename = "LoTESequenceNumber")]
    pub lote_sequence_number: u64,

    #[serde(rename = "LoTEType")]
    pub lote_type: Option<LoTEType>,

    #[serde(rename = "SchemeOperatorName")]
    pub scheme_operator_name: MultiLangNameList,

    #[serde(rename = "SchemeInformationURI")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub scheme_information_uri: Option<MultiLangUriList>,

    #[serde(rename = "StatusDeterminationApproach")]
    pub status_determination_approach: String,

    #[serde(rename = "SchemeTypeCommunityRules")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub scheme_type_community_rules: Option<MultiLangUriList>,

    #[serde(rename = "SchemeTerritory")]
    pub scheme_territory: Option<String>,

    #[serde(rename = "SchemeOperatorAddress")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub scheme_operator_address: Option<SchemeOperatorAddress>,

    #[serde(rename = "SchemeName")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub scheme_name: Option<MultiLangNameList>,

    #[serde(rename = "PolicyOrLegalNotice")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub policy_or_legal_notice: Option<PolicyOrLegalNotice>,

    #[serde(rename = "HistoricalInformationPeriod")]
    pub historical_information_period: Option<u64>,

    #[serde(rename = "PointersToOtherLoTE")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub pointers_to_other_lote: Option<PointersToOtherLoTE>,

    #[serde(rename = "DistributionPoints")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub distribution_points: Option<UriList>,

    #[serde(rename = "SchemeExtensions")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub scheme_extensions: Option<ExtensionsList>,

    #[serde(rename = "ListIssueDateTime", with = "time::serde::rfc3339")]
    pub list_issue_date_time: OffsetDateTime,

    #[serde(rename = "NextUpdate")]
    pub next_update: NextUpdate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MultiLangNameList {
    #[serde(rename = "Name", default)]
    pub names: Vec<MultiLangString>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MultiLangUriList {
    #[serde(rename = "URI", default)]
    pub uris: Vec<MultiLangUri>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct UriList {
    #[serde(rename = "URI", default)]
    pub uris: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PostalAddresses {
    #[serde(rename = "PostalAddress", default)]
    pub addresses: Vec<PostalAddress>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NextUpdate {
    #[serde(rename = "dateTime", with = "time::serde::rfc3339")]
    pub date_time: OffsetDateTime,
}

/// XSD `ExtensionsListType` — wraps a sequence of `<Extension>` elements.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ExtensionsList {
    #[serde(rename = "Extension", default)]
    pub extensions: Vec<Extension>,
}

/// LoTE qualifier information extracted from `<AdditionalInformation>/<OtherInformation>`.
///
/// Custom Serialize/Deserialize impls live in `convert.rs` to work around
/// quick-xml's inability to serialize enum variants with data: the XML uses a
/// sequence of `<OtherInformation>` elements (one per field), which is
/// bridged through intermediate raw structs at serialization boundaries.
#[derive(Clone, Debug, PartialEq)]
pub struct AdditionalInformation {
    pub lote_type: Option<String>,
    pub scheme_operator_name: Option<MultiLangNameList>,
    pub mime_type: Option<String>,
    pub scheme_type_community_rules: Option<MultiLangUriList>,
    pub scheme_territory: Option<String>,
}

/// Flat representation of digital identities, mirroring the JSON schema.
///
/// Custom Serialize/Deserialize impls in `convert.rs` handle the XML wire
/// format where each value is wrapped in its own `<DigitalId>` element.
#[derive(Debug, Default, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::ServiceDigitalIdentity)]
#[into(super::json::ServiceDigitalIdentity)]
pub struct ServiceDigitalIdentity {
    #[from(with_fn = "convert_inner_of_inner")]
    #[into(with_fn = "convert_inner_of_inner")]
    pub x509_certificates: Option<Vec<String>>,
    pub x509_subject_names: Option<Vec<String>>,
    pub public_key_values: Option<Vec<serde_json::Value>>,
    pub x509_skis: Option<Vec<String>>,
    pub other_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceSupplyPoints {
    #[serde(rename = "ServiceSupplyPoint", default)]
    pub points: Vec<ServiceSupplyPoint>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyOrLegalNotice {
    #[serde(rename = "$value", default)]
    pub items: Vec<PolicyOrLegalNoticeItem>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum PolicyOrLegalNoticeItem {
    LoTEPolicy(MultiLangUri),
    LoTELegalNotice(MultiLangString),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustedEntitiesList {
    #[serde(rename = "TrustedEntity", default)]
    pub entities: Vec<TrustedEntity>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct TrustedEntityServices {
    #[serde(rename = "TrustedEntityService", default)]
    pub services: Vec<TrustedEntityService>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceHistory {
    #[serde(rename = "ServiceHistoryInstance", default)]
    pub instances: Vec<ServiceHistoryInstance>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PointersToOtherLoTE {
    #[serde(rename = "OtherLoTEPointer", default)]
    pub pointers: Vec<OtherLoTEPointer>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceDigitalIdentities {
    #[serde(rename = "ServiceDigitalIdentity", default)]
    pub identities: Vec<ServiceDigitalIdentity>,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into,
)]
#[from(super::json::MultiLangString)]
#[into(super::json::MultiLangString)]
pub struct MultiLangString {
    #[serde(rename = "@xml:lang")]
    pub lang: String,
    #[serde(rename = "$text")]
    pub value: String,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into,
)]
#[from(super::json::MultiLangUri)]
#[into(super::json::MultiLangUri)]
pub struct MultiLangUri {
    #[serde(rename = "@xml:lang")]
    pub lang: String,
    #[serde(rename = "$text")]
    pub uri_value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::SchemeOperatorAddress)]
#[into(super::json::SchemeOperatorAddress)]
pub struct SchemeOperatorAddress {
    #[serde(rename = "PostalAddresses")]
    pub scheme_operator_postal_address: PostalAddresses,

    #[serde(rename = "ElectronicAddress")]
    pub scheme_operator_electronic_address: MultiLangUriList,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[serde_with::skip_serializing_none]
#[from(super::json::Extension)]
#[into(super::json::Extension)]
pub struct Extension {
    #[serde(rename = "@Critical")]
    pub critical: bool,

    #[serde(rename = "$value", default)]
    pub content: Option<serde_json::Value>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::TEAddress)]
#[into(super::json::TEAddress)]
pub struct TEAddress {
    #[serde(rename = "PostalAddresses")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub te_postal_address: Option<PostalAddresses>,

    #[serde(rename = "ElectronicAddress")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub te_electronic_address: Option<MultiLangUriList>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::PostalAddress)]
#[into(super::json::PostalAddress)]
#[serde(rename_all = "PascalCase")]
pub struct PostalAddress {
    pub street_address: String,
    pub locality: Option<String>,
    pub state_or_province: Option<String>,
    pub postal_code: Option<String>,

    #[serde(rename = "@xml:lang")]
    pub lang: String,

    #[serde(rename = "CountryName")]
    pub country: String,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::ServiceSupplyPoint)]
#[into(super::json::ServiceSupplyPoint)]
pub struct ServiceSupplyPoint {
    #[serde(rename = "@type")]
    pub service_type: Option<String>,

    #[serde(rename = "$text")]
    pub uri_value: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::TrustedEntity)]
#[into(super::json::TrustedEntity)]
#[serde(rename_all = "PascalCase")]
pub struct TrustedEntity {
    pub trusted_entity_information: TrustedEntityInformation,
    pub trusted_entity_services: TrustedEntityServices,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::TrustedEntityInformation)]
#[into(super::json::TrustedEntityInformation)]
pub struct TrustedEntityInformation {
    #[serde(rename = "TEName")]
    pub te_name: MultiLangNameList,

    #[serde(rename = "TEInformationURI")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub te_information_uri: Option<MultiLangUriList>,

    #[serde(rename = "TEAddress")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub te_address: Option<TEAddress>,

    #[serde(rename = "TETradeName")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub te_trade_name: Option<MultiLangNameList>,

    #[serde(rename = "TEInformationExtensions")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub te_information_extensions: Option<ExtensionsList>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::TrustedEntityService)]
#[into(super::json::TrustedEntityService)]
#[serde(rename_all = "PascalCase")]
pub struct TrustedEntityService {
    pub service_information: ServiceInformation,

    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub service_history: Option<ServiceHistory>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::ServiceInformation)]
#[into(super::json::ServiceInformation)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceInformation {
    pub service_type_identifier: Option<String>,
    pub service_name: MultiLangNameList,

    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub service_digital_identity: Option<ServiceDigitalIdentity>,

    pub service_status: Option<ServiceStatus>,

    #[serde(default, with = "crate::mapper::xml_datetime::option")]
    pub status_starting_time: Option<OffsetDateTime>,

    #[serde(rename = "SchemeServiceDefinitionURI")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub scheme_service_definition_uri: Option<MultiLangUriList>,

    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub service_supply_points: Option<ServiceSupplyPoints>,

    #[serde(rename = "TEServiceDefinitionURI")]
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub service_definition_uri: Option<MultiLangUriList>,

    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub service_information_extensions: Option<ExtensionsList>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, one_dto_mapper::From, one_dto_mapper::Into)]
#[from(super::json::ServiceHistoryInstance)]
#[into(super::json::ServiceHistoryInstance)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceHistoryInstance {
    pub service_type_identifier: Option<String>,
    pub service_name: MultiLangNameList,
    pub service_digital_identity: ServiceDigitalIdentity,
    pub service_status: ServiceStatus,

    #[serde(with = "time::serde::rfc3339")]
    pub status_starting_time: OffsetDateTime,

    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub service_information_extensions: Option<ExtensionsList>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "PascalCase")]
pub struct OtherLoTEPointer {
    pub service_digital_identities: ServiceDigitalIdentities,
    pub additional_information: Option<AdditionalInformation>,

    #[serde(rename = "LoTELocation")]
    pub lote_location: String,
}

#[cfg(test)]
mod test;
