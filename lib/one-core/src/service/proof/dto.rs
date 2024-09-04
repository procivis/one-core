use std::collections::HashMap;

use dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{DidId, KeyId, OrganisationId, ProofId, ProofSchemaId};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::common::GetListResponse;
use crate::model::interaction::InteractionId;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListQuery;
use crate::model::proof::{ProofStateEnum, SortableProofColumn};
use crate::provider::bluetooth_low_energy::low_level::dto::DeviceAddress;
use crate::provider::credential_formatter::mdoc_formatter::mdoc::EmbeddedCbor;
use crate::provider::exchange_protocol::iso_mdl::{
    self,
    common::{SkDevice, SkReader},
};
use crate::service::credential::dto::CredentialDetailResponseDTO;
use crate::service::credential_schema::dto::CredentialSchemaListItemResponseDTO;
use crate::service::did::dto::DidListItemResponseDTO;
use crate::service::proof_schema::dto::{GetProofSchemaListItemDTO, ProofClaimSchemaResponseDTO};

#[derive(Clone, Debug)]
pub struct CreateProofRequestDTO {
    pub proof_schema_id: ProofSchemaId,
    pub verifier_did_id: DidId,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub verifier_key: Option<KeyId>,
    pub scan_to_verify: Option<ScanToVerifyRequestDTO>,
    pub iso_mdl_engagement: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanToVerifyRequestDTO {
    pub credential: String,
    pub barcode: String,
    pub barcode_type: ScanToVerifyBarcodeTypeEnum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanToVerifyBarcodeTypeEnum {
    MRZ,
    PDF417,
}

#[derive(Clone, Debug)]
pub struct CreateProofResponseDTO {
    pub id: ProofId,
}

#[derive(Clone, Debug)]
pub struct ProofDetailResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier_did: Option<DidListItemResponseDTO>,
    pub holder_did_id: Option<DidId>,
    pub exchange: String,
    pub transport: String,
    pub state: ProofStateEnum,
    pub organisation_id: Option<OrganisationId>,
    pub schema: Option<GetProofSchemaListItemDTO>,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofListItemResponseDTO {
    pub id: ProofId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub verifier_did: Option<DidListItemResponseDTO>,
    pub exchange: String,
    pub transport: String,
    pub state: ProofStateEnum,
    pub schema: Option<GetProofSchemaListItemDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofClaimDTO {
    pub schema: ProofClaimSchemaResponseDTO,
    pub path: String,
    pub value: Option<ProofClaimValueDTO>,
}

#[derive(Clone, Debug)]
pub enum ProofClaimValueDTO {
    Value(String),
    Claims(Vec<ProofClaimDTO>),
}

#[derive(Clone, Debug)]
pub struct ProofInputDTO {
    pub claims: Vec<ProofClaimDTO>,
    pub credential: Option<CredentialDetailResponseDTO>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
    pub validity_constraint: Option<i64>,
}

pub type GetProofListResponseDTO = GetListResponse<ProofListItemResponseDTO>;

#[derive(Debug, Clone)]
pub enum ProofFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    ProofStates(Vec<ProofStateEnum>),
    ProofIds(Vec<ProofId>),
    ProofSchemaIds(Vec<ProofSchemaId>),
}

impl ListFilterValue for ProofFilterValue {}

pub type GetProofQueryDTO = ListQuery<SortableProofColumn, ProofFilterValue>;

#[derive(Clone, Debug)]
pub struct ProposeProofResponseDTO {
    pub proof_id: ProofId,
    pub interaction_id: InteractionId,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdocBleInteractionData {
    pub service_id: Uuid,
    pub task_id: Uuid,
    pub sk_device: SkDevice,
    pub sk_reader: SkReader,
    pub device_request: DeviceRequest,
    pub device_address: Option<DeviceAddress>,
    pub organisation_id: OrganisationId,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, From, Into)]
#[from(iso_mdl::common::DeviceRequest)]
#[into(iso_mdl::common::DeviceRequest)]
pub struct DeviceRequest {
    pub version: String,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub doc_request: Vec<DocRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, From, Into)]
#[from(iso_mdl::common::DocRequest)]
#[into(iso_mdl::common::DocRequest)]
pub struct DocRequest {
    pub items_request: ItemsRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize, From, Into)]
#[from(iso_mdl::common::ItemsRequest)]
#[into(iso_mdl::common::ItemsRequest)]
pub struct ItemsRequest {
    pub doc_type: String,
    pub name_spaces: HashMap<String, HashMap<String, bool>>,
}

impl From<ItemsRequest> for EmbeddedCbor<iso_mdl::common::ItemsRequest> {
    fn from(value: ItemsRequest) -> Self {
        Self(value.into())
    }
}

impl From<EmbeddedCbor<iso_mdl::common::ItemsRequest>> for ItemsRequest {
    fn from(EmbeddedCbor(value): EmbeddedCbor<iso_mdl::common::ItemsRequest>) -> Self {
        value.into()
    }
}
