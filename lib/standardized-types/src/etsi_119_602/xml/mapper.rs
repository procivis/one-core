use one_dto_mapper::convert_inner;
use time::OffsetDateTime;

use crate::etsi_119_602::{json, xml};

// XML requires a parent element around repeated children, so each of these
// wrapper structs holds a single Vec field. The macro generates the symmetric
// From impls that wrap/unwrap + convert the inner items.
macro_rules! impl_xml_list_wrapper {
    ($json_item:ty, $xml_wrapper:ty, $field:ident) => {
        impl From<Vec<$json_item>> for $xml_wrapper {
            fn from(v: Vec<$json_item>) -> Self {
                Self {
                    $field: convert_inner(v),
                }
            }
        }
        impl From<$xml_wrapper> for Vec<$json_item> {
            fn from(w: $xml_wrapper) -> Self {
                convert_inner(w.$field)
            }
        }
    };
}

impl_xml_list_wrapper!(json::MultiLangString, xml::MultiLangNameList, names);
impl_xml_list_wrapper!(json::MultiLangUri, xml::MultiLangUriList, uris);
impl_xml_list_wrapper!(json::PostalAddress, xml::PostalAddresses, addresses);
impl_xml_list_wrapper!(json::ServiceSupplyPoint, xml::ServiceSupplyPoints, points);
impl_xml_list_wrapper!(json::TrustedEntity, xml::TrustedEntitiesList, entities);
impl_xml_list_wrapper!(
    json::TrustedEntityService,
    xml::TrustedEntityServices,
    services
);
impl_xml_list_wrapper!(json::ServiceHistoryInstance, xml::ServiceHistory, instances);
impl_xml_list_wrapper!(json::OtherLoTEPointer, xml::PointersToOtherLoTE, pointers);
impl_xml_list_wrapper!(
    json::ServiceDigitalIdentity,
    xml::ServiceDigitalIdentities,
    identities
);
impl_xml_list_wrapper!(
    json::PolicyOrLegalNoticeItem,
    xml::PolicyOrLegalNotice,
    items
);
impl_xml_list_wrapper!(String, xml::UriList, uris);
impl_xml_list_wrapper!(json::Extension, xml::ExtensionsList, extensions);

impl From<json::PkiObject> for String {
    fn from(p: json::PkiObject) -> Self {
        p.val
    }
}

impl From<String> for json::PkiObject {
    fn from(val: String) -> Self {
        Self {
            val,
            ..Default::default()
        }
    }
}

impl From<OffsetDateTime> for xml::NextUpdate {
    fn from(dt: OffsetDateTime) -> Self {
        Self { date_time: dt }
    }
}

impl From<xml::NextUpdate> for OffsetDateTime {
    fn from(w: xml::NextUpdate) -> Self {
        w.date_time
    }
}

// The JSON schema defines LoTELegalNotice as a bare string
// The XML schema defines LoTELegalNotice as a multi lang string with lang required
impl From<json::PolicyOrLegalNoticeItem> for xml::PolicyOrLegalNoticeItem {
    fn from(item: json::PolicyOrLegalNoticeItem) -> Self {
        match item {
            json::PolicyOrLegalNoticeItem::Policy { lote_policy } => {
                Self::LoTEPolicy(lote_policy.into())
            }
            json::PolicyOrLegalNoticeItem::LegalNotice { lote_legal_notice } => {
                Self::LoTELegalNotice(xml::MultiLangString {
                    lang: "en".into(),
                    value: lote_legal_notice,
                })
            }
        }
    }
}

impl From<xml::PolicyOrLegalNoticeItem> for json::PolicyOrLegalNoticeItem {
    fn from(item: xml::PolicyOrLegalNoticeItem) -> Self {
        match item {
            xml::PolicyOrLegalNoticeItem::LoTEPolicy(uri) => Self::Policy {
                lote_policy: uri.into(),
            },
            xml::PolicyOrLegalNoticeItem::LoTELegalNotice(s) => Self::LegalNotice {
                lote_legal_notice: s.value,
            },
        }
    }
}

impl From<json::OtherLoTEPointer> for xml::OtherLoTEPointer {
    fn from(p: json::OtherLoTEPointer) -> Self {
        // The JSON binding allows several qualifier sets, the XML binding a single one.
        // We map the first; it is unclear whether any deployment will publish more than one.
        let q = p.lote_qualifiers.into_iter().next();
        Self {
            service_digital_identities: p.service_digital_identities.into(),
            lote_location: p.lote_location,
            additional_information: q.map(|q| xml::AdditionalInformation {
                lote_type: Some(q.lote_type),
                scheme_operator_name: Some(q.scheme_operator_name.into()),
                mime_type: Some(q.mime_type),
                scheme_type_community_rules: q.scheme_type_community_rules.map(Into::into),
                scheme_territory: q.scheme_territory,
            }),
        }
    }
}

impl From<xml::OtherLoTEPointer> for json::OtherLoTEPointer {
    fn from(p: xml::OtherLoTEPointer) -> Self {
        let a = p
            .additional_information
            .unwrap_or(xml::AdditionalInformation {
                lote_type: None,
                scheme_operator_name: None,
                mime_type: None,
                scheme_type_community_rules: None,
                scheme_territory: None,
            });
        Self {
            service_digital_identities: p.service_digital_identities.into(),
            lote_location: p.lote_location,
            lote_qualifiers: vec![json::LoTEQualifier {
                lote_type: a.lote_type.unwrap_or_default(),
                scheme_operator_name: a.scheme_operator_name.map(Into::into).unwrap_or_default(),
                mime_type: a.mime_type.unwrap_or_default(),
                scheme_type_community_rules: a.scheme_type_community_rules.map(Into::into),
                scheme_territory: a.scheme_territory,
            }],
        }
    }
}

impl From<json::LoTEPayload> for xml::LoTEPayload {
    fn from(p: json::LoTEPayload) -> Self {
        Self {
            xmlns: xml::LOTE_NS.to_string(),
            lote_tag: xml::LOTE_TAG.to_string(),
            list_and_scheme_information: p.list_and_scheme_information.into(),
            trusted_entities_list: p.trusted_entities_list.map(Into::into),
        }
    }
}

impl From<xml::LoTEPayload> for json::LoTEPayload {
    fn from(p: xml::LoTEPayload) -> Self {
        Self {
            list_and_scheme_information: p.list_and_scheme_information.into(),
            trusted_entities_list: p.trusted_entities_list.map(Into::into),
        }
    }
}
