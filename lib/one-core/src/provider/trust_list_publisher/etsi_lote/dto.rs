use serde::{Deserialize, Serialize};
use standardized_types::etsi_119_602::{
    MultiLangString, MultiLangUri, OtherLoTEPointer, PolicyOrLegalNoticeItem,
    SchemeOperatorAddress, ServiceSupplyPoint, TEAddress,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct AddEntryParams {
    pub entity: EntityInfoParams,
    pub service: ServiceInfoParams,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct EntityInfoParams {
    pub name: Option<Vec<MultiLangString>>,
    pub information_uri: Option<Vec<MultiLangUri>>,
    pub trade_name: Option<Vec<MultiLangString>>,
    pub address: Option<TEAddress>,
    pub extensions: Option<Vec<serde_json::Value>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ServiceInfoParams {
    pub name: Option<Vec<MultiLangString>>,
    pub supply_points: Option<Vec<ServiceSupplyPoint>>,
    pub definition_uri: Option<Vec<MultiLangUri>>,
    pub scheme_definition_uri: Option<Vec<MultiLangUri>>,
    pub extensions: Option<Vec<serde_json::Value>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct CreateTrustListParams {
    pub scheme_operator_name: Option<Vec<MultiLangString>>,
    pub scheme_name: Option<Vec<MultiLangString>>,
    pub scheme_territory: Option<String>,
    pub scheme_information_uri: Option<Vec<MultiLangUri>>,
    pub scheme_operator_address: Option<SchemeOperatorAddress>,
    pub policy_or_legal_notice: Option<Vec<PolicyOrLegalNoticeItem>>,
    pub historical_information_period: Option<u64>,
    pub pointers_to_other_lote: Option<Vec<OtherLoTEPointer>>,
    pub distribution_points: Option<Vec<String>>,
    pub scheme_extensions: Option<Vec<serde_json::Value>>,
}
