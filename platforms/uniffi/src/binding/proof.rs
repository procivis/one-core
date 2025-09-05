use std::collections::HashMap;

use one_core::model::common::{EntityShareResponseDTO, ExactColumn};
use one_core::model::proof::{ProofRole, ProofStateEnum, SortableProofColumn};
use one_core::provider::verification_protocol::dto::{
    PresentationDefinitionRequestGroupResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
};
use one_core::provider::verification_protocol::openid4vp::model::ClientIdScheme;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::{
    CreateProofRequestDTO, GetProofListResponseDTO, ProofInputDTO, ProofListItemResponseDTO,
    ProposeProofResponseDTO, ScanToVerifyBarcodeTypeEnum, ScanToVerifyRequestDTO,
    ShareProofRequestDTO, ShareProofRequestParamsDTO,
};
use one_core::service::ssi_holder::dto::{
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner_of_inner};

use super::common::SortDirection;
use super::credential::CredentialDetailBindingDTO;
use super::credential_schema::CredentialSchemaBindingDTO;
use super::identifier::GetIdentifierListItemBindingDTO;
use super::mapper::{optional_identifier_id_string, optional_time};
use super::proof_schema::{GetProofSchemaListItemBindingDTO, ProofRequestClaimBindingDTO};
use crate::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id, into_id_opt};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_proof(
        &self,
        request: CreateProofRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;
        let core = self.use_core().await?;
        Ok(core.proof_service.create_proof(request).await?.to_string())
    }

    #[uniffi::method]
    pub async fn get_proof(
        &self,
        proof_id: String,
    ) -> Result<ProofResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let proof = core.proof_service.get_proof(&into_id(&proof_id)?).await?;
        Ok(proof.into())
    }

    #[uniffi::method]
    pub async fn delete_proof(&self, proof_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        core.proof_service.delete_proof(into_id(&proof_id)?).await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn get_proofs(
        &self,
        query: ProofListQueryBindingDTO,
    ) -> Result<ProofListBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let proofs = core.proof_service.get_proof_list(query.try_into()?).await?;
        Ok(proofs.into())
    }

    #[uniffi::method]
    pub async fn holder_reject_proof(&self, interaction_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .reject_proof_request(&into_id(&interaction_id)?)
            .await?)
    }

    #[uniffi::method]
    pub async fn holder_submit_proof(
        &self,
        interaction_id: String,
        submit_credentials: HashMap<String, Vec<PresentationSubmitCredentialRequestBindingDTO>>,
        did_id: Option<String>,
        identifier_id: Option<String>,
        key_id: Option<String>,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        core.ssi_holder_service
            .submit_proof(PresentationSubmitRequestDTO {
                interaction_id: into_id(&interaction_id)?,
                submit_credentials: try_convert_inner_of_inner(submit_credentials)?,
                did_id: did_id.map(into_id).transpose()?,
                identifier_id: identifier_id.map(into_id).transpose()?,
                key_id: key_id.map(|key_id| into_id(&key_id)).transpose()?,
            })
            .await?;

        Ok(())
    }

    #[uniffi::method]
    pub async fn propose_proof(
        &self,
        exchange: String,
        organisation_id: String,
        engagement: Vec<String>,
    ) -> Result<ProposeProofResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .proof_service
            .propose_proof(exchange, into_id(&organisation_id)?, engagement)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn share_proof(
        &self,
        proof_id: String,
        params: ShareProofRequestBindingDTO,
    ) -> Result<ShareProofResponseBindingDTO, BindingError> {
        let id = into_id(&proof_id)?;
        let core = self.use_core().await?;
        let response = core.proof_service.share_proof(&id, params.into()).await?;
        Ok(ShareProofResponseBindingDTO::from(response))
    }

    #[uniffi::method]
    pub async fn delete_proof_claims(&self, proof_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        core.proof_service
            .delete_proof_claims(into_id(&proof_id)?)
            .await?;
        Ok(())
    }

    #[uniffi::method]
    pub async fn get_presentation_definition(
        &self,
        proof_id: String,
    ) -> Result<PresentationDefinitionBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .proof_service
            .get_proof_presentation_definition(&into_id(&proof_id)?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateProofRequestDTO, Error = ServiceError)]
pub struct CreateProofRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub proof_schema_id: String,
    #[try_into(with_fn = into_id_opt)]
    pub verifier_did_id: Option<String>,
    #[try_into(with_fn = into_id_opt)]
    pub verifier_identifier_id: Option<String>,
    #[try_into(infallible)]
    pub protocol: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub redirect_uri: Option<String>,
    #[try_into(with_fn = into_id_opt)]
    pub verifier_key: Option<String>,
    #[try_into(with_fn = into_id_opt)]
    pub verifier_certificate: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub scan_to_verify: Option<ScanToVerifyRequestBindingDTO>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub iso_mdl_engagement: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub transport: Option<Vec<String>>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub profile: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub engagement: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(ScanToVerifyRequestDTO)]
pub struct ScanToVerifyRequestBindingDTO {
    pub credential: String,
    pub barcode: String,
    pub barcode_type: ScanToVerifyBarcodeTypeBindingEnum,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ScanToVerifyBarcodeTypeEnum)]
pub enum ScanToVerifyBarcodeTypeBindingEnum {
    #[allow(clippy::upper_case_acronyms)]
    MRZ,
    PDF417,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
pub enum ProofListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableProofColumn)]
pub enum SortableProofListColumnBinding {
    SchemaName,
    Verifier,
    State,
    CreatedDate,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProofListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub sort: Option<SortableProofListColumnBinding>,
    pub sort_direction: Option<SortDirection>,
    pub name: Option<String>,
    pub profile: Option<String>,
    pub ids: Option<Vec<String>>,
    pub proof_states: Option<Vec<ProofStateBindingEnum>>,
    pub proof_roles: Option<Vec<ProofRoleBindingEnum>>,
    pub proof_schema_ids: Option<Vec<String>>,
    pub exact: Option<Vec<ProofListQueryExactColumnBindingEnum>>,

    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
    pub requested_date_after: Option<String>,
    pub requested_date_before: Option<String>,
    pub completed_date_after: Option<String>,
    pub completed_date_before: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofListItemResponseDTO)]
pub struct ProofListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn = optional_time)]
    pub requested_date: Option<String>,
    #[from(with_fn = optional_time)]
    pub completed_date: Option<String>,
    #[from(with_fn = optional_identifier_id_string)]
    pub verifier: Option<String>,
    pub protocol: String,
    pub transport: String,
    pub engagement: Option<String>,
    pub state: ProofStateBindingEnum,
    pub role: ProofRoleBindingEnum,
    #[from(with_fn = convert_inner)]
    pub schema: Option<GetProofSchemaListItemBindingDTO>,
    #[from(with_fn = optional_time)]
    pub retain_until_date: Option<String>,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ProofResponseBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub verifier: Option<GetIdentifierListItemBindingDTO>,
    pub holder: Option<GetIdentifierListItemBindingDTO>,
    pub state: ProofStateBindingEnum,
    pub role: ProofRoleBindingEnum,
    pub proof_schema: Option<GetProofSchemaListItemBindingDTO>,
    pub protocol: String,
    pub engagement: Option<String>,
    pub transport: String,
    pub redirect_uri: Option<String>,
    pub proof_inputs: Vec<ProofInputBindingDTO>,
    pub retain_until_date: Option<String>,
    pub requested_date: Option<String>,
    pub completed_date: Option<String>,
    pub claims_removed_at: Option<String>,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofInputDTO)]
pub struct ProofInputBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub credential: Option<CredentialDetailBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofListResponseDTO)]
pub struct ProofListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<ProofListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
pub enum ProofStateBindingEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Retracted,
    Error,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(ProofRole)]
#[into(ProofRole)]
pub enum ProofRoleBindingEnum {
    Holder,
    Verifier,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = PresentationSubmitCredentialRequestDTO, Error = ServiceError)]
pub struct PresentationSubmitCredentialRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_id: String,
    #[try_into(infallible)]
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProposeProofResponseDTO)]
pub struct ProposeProofResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub proof_id: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub interaction_id: String,
    pub url: Option<String>,
}

#[derive(Into, uniffi::Record)]
#[into(ShareProofRequestDTO)]
pub struct ShareProofRequestBindingDTO {
    #[into(with_fn = "convert_inner")]
    pub params: Option<ShareProofRequestParamsBindingDTO>,
}

#[derive(Into, uniffi::Record)]
#[into(ShareProofRequestParamsDTO)]
pub struct ShareProofRequestParamsBindingDTO {
    #[into(with_fn = "convert_inner")]
    pub client_id_scheme: Option<ClientIdSchemeBindingEnum>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ClientIdScheme)]
pub enum ClientIdSchemeBindingEnum {
    RedirectUri,
    VerifierAttestation,
    Did,
    X509SanDns,
}

#[derive(From, uniffi::Record)]
#[from(EntityShareResponseDTO)]
pub struct ShareProofResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionResponseDTO)]
pub struct PresentationDefinitionBindingDTO {
    #[from(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub credentials: Vec<CredentialDetailBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRequestGroupResponseDTO)]
pub struct PresentationDefinitionRequestGroupBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleBindingDTO,
    #[from(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PresentationDefinitionRequestedCredentialBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub fields: Vec<PresentationDefinitionFieldBindingDTO>,
    pub applicable_credentials: Vec<String>,
    pub inapplicable_credentials: Vec<String>,
    pub validity_credential_nbf: Option<String>,
    pub multiple: Option<bool>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct PresentationDefinitionFieldBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: bool,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(PresentationDefinitionRuleTypeEnum)]
pub enum PresentationDefinitionRuleTypeBindingEnum {
    All,
    Pick,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRuleDTO)]
pub struct PresentationDefinitionRuleBindingDTO {
    pub r#type: PresentationDefinitionRuleTypeBindingEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}
