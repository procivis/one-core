use std::collections::HashMap;

use one_core::model::common::ExactColumn;
use one_core::model::proof::{ProofRole, ProofStateEnum, SortableProofColumn};
use one_core::provider::verification_protocol::dto::{
    CredentialDetailClaimExtResponseDTO, CredentialQueryFailureHintResponseDTO,
    CredentialQueryFailureReasonEnum, CredentialQueryResponseDTO, CredentialSetResponseDTO,
    PresentationDefinitionRequestGroupResponseDTO, PresentationDefinitionResponseDTO,
    PresentationDefinitionRuleDTO, PresentationDefinitionRuleTypeEnum,
    PresentationDefinitionV2ResponseDTO,
};
use one_core::provider::verification_protocol::openid4vp::model::ClientIdScheme;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::{
    GetProofListResponseDTO, ProofClaimDTO, ProofInputDTO, ProofListItemResponseDTO,
    ProposeProofRequestDTO, ProposeProofResponseDTO, ShareProofRequestDTO,
    ShareProofRequestParamsDTO, ShareProofResponseDTO,
};
use one_core::service::ssi_holder::dto::{
    PresentationSubmitCredentialRequestDTO, PresentationSubmitRequestDTO,
    PresentationSubmitV2CredentialRequestDTO, PresentationSubmitV2RequestDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner_of_inner};

use super::common::SortDirection;
use super::credential::{
    CredentialDetailBindingDTO, CredentialRoleBindingDTO, CredentialStateBindingEnum,
    MdocMsoValidityResponseBindingDTO,
};
use super::credential_schema::{
    CredentialClaimSchemaBindingDTO, CredentialSchemaBindingDTO, CredentialSchemaDetailBindingDTO,
};
use super::identifier::{CertificateResponseBindingDTO, GetIdentifierListItemBindingDTO};
use super::mapper::{optional_identifier_id_string, optional_time};
use super::proof_schema::{GetProofSchemaListItemBindingDTO, ProofClaimSchemaBindingDTO};
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// For verifiers, creates a proof request. Choose what information to
    /// request via a proof schema, an identifier, and which protocol to use
    /// for making the request.
    #[uniffi::method]
    pub async fn create_proof(
        &self,
        request: CreateProofRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;
        let core = self.use_core().await?;
        Ok(core.proof_service.create_proof(request).await?.to_string())
    }

    /// Returns detailed information about a proof request.
    #[uniffi::method]
    pub async fn get_proof(
        &self,
        proof_id: String,
    ) -> Result<ProofResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let proof = core.proof_service.get_proof(&into_id(&proof_id)?).await?;
        Ok(proof.into())
    }

    /// Deletes an incomplete proof request. If the request is in `REQUESTED`
    /// state the proof is retracted instead, retaining history of the interaction.
    #[uniffi::method]
    pub async fn delete_proof(&self, proof_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        core.proof_service.delete_proof(into_id(&proof_id)?).await?;
        Ok(())
    }

    /// Returns a filterable list of proof requests.
    #[uniffi::method]
    pub async fn list_proofs(
        &self,
        query: ProofListQueryBindingDTO,
    ) -> Result<ProofListBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let organisation_id = into_id(query.organisation_id.clone())?;
        let proofs = core
            .proof_service
            .get_proof_list(&organisation_id, query.try_into()?)
            .await?;
        Ok(proofs.into())
    }

    /// Rejects a proof request.
    #[uniffi::method]
    pub async fn holder_reject_proof(&self, interaction_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .reject_proof_request(&into_id(&interaction_id)?)
            .await?)
    }

    /// Submits a presentation using Presentation Exchange as the query
    /// language; this should be used after `getPresentationDefinition`.
    #[uniffi::method]
    pub async fn holder_submit_proof(
        &self,
        interaction_id: String,
        submit_credentials: HashMap<String, Vec<PresentationSubmitCredentialRequestBindingDTO>>,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        core.ssi_holder_service
            .submit_proof(PresentationSubmitRequestDTO {
                interaction_id: into_id(&interaction_id)?,
                submit_credentials: try_convert_inner_of_inner(submit_credentials)?,
            })
            .await?;

        Ok(())
    }

    /// Submits a presentation using DCQL as a query language; this should
    /// be used after `getPresentationDefinitionv2`.
    #[uniffi::method]
    pub async fn holder_submit_proof_v2(
        &self,
        interaction_id: String,
        submission: HashMap<String, Vec<PresentationSubmitV2CredentialRequestBindingDTO>>,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;

        core.ssi_holder_service
            .submit_proof_v2(PresentationSubmitV2RequestDTO {
                interaction_id: into_id(&interaction_id)?,
                submission: try_convert_inner_of_inner(submission)?,
            })
            .await?;

        Ok(())
    }

    /// For wallets, initiates device engagement for offline flows. Reference
    /// the `verificationEngagement` entry of your configuration for your
    /// options for `engagement`.
    #[uniffi::method]
    pub async fn propose_proof(
        &self,
        request: ProposeProofRequestBindingDTO,
    ) -> Result<ProposeProofResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .proof_service
            .propose_proof(request.try_into()?)
            .await?
            .into())
    }

    /// Creates a share URL from a proof request. A wallet holder can use this
    /// URL to access the request.
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

    #[uniffi::method]
    pub async fn get_presentation_definition_v2(
        &self,
        proof_id: String,
    ) -> Result<PresentationDefinitionV2ResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .proof_service
            .get_proof_presentation_definition_v2(&into_id(&proof_id)?)
            .await?
            .into())
    }
}

/// If protocol is `ISO_MDL`, specify the device engagement type
/// by referencing an entry from `verificationEngagement` of your
/// configuration. `iso_mdl_engagement` accepts either QR code content
/// (for QR device engagement) or NFC engagement parameters from
/// `nfc_read_iso_mdl_engagement`.
#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateProofRequest")]
pub struct CreateProofRequestBindingDTO {
    /// Choose a proof schema to use.
    pub proof_schema_id: String,
    /// Deprecated. Use `verifierIdentifierId`.
    pub verifier_did_id: Option<String>,
    /// Choose the identifier to use to make the request.
    pub verifier_identifier_id: Option<String>,
    /// Choose the protocol to use for verification. Check the
    /// `verificationProtocol` object of your configuration for
    /// supported options and reference the configuration instance.
    pub protocol: String,
    /// When a shared proof is accepted, the wallet will be redirected
    /// to the resource specified here, if redirects are enabled in the
    /// configuration. The URI must use a scheme that is allowed by the
    /// configuration.
    pub redirect_uri: Option<String>,
    /// If the identifier contains multiple keys, use this to specify
    /// which key to use. If omitted, the first suitable key is used.
    pub verifier_key: Option<String>,
    /// If the identifier contains multiple certificates, use this to
    /// specify which key to use. If omitted, the first suitable
    /// certificate is used.
    pub verifier_certificate: Option<String>,
    /// Use to specify device engagement type.
    pub iso_mdl_engagement: Option<String>,
    /// Choose the transport protocol for the exchange. Check the
    /// `transport` object of your configuration for supported
    /// options and reference the configuration instance.
    pub transport: Option<Vec<String>>,
    /// Country profile to associate with this request.
    pub profile: Option<String>,
    /// Use for ISO mDL verification over BLE.
    pub engagement: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
#[uniffi(name = "ProofListQueryExactColumn")]
pub enum ProofListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableProofColumn)]
#[uniffi(name = "SortableProofColumn")]
pub enum SortableProofListColumnBinding {
    SchemaName,
    Verifier,
    State,
    CreatedDate,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "ProofListQuery")]
pub struct ProofListQueryBindingDTO {
    /// Page number to retrieve (0-based indexing).
    pub page: u32,
    /// Number of items to return per page.
    pub page_size: u32,
    /// Specifies the organizational context for this operation.
    pub organisation_id: String,
    /// Field value to sort results by.
    pub sort: Option<SortableProofListColumnBinding>,
    /// Direction to sort results by.
    pub sort_direction: Option<SortDirection>,
    /// Return only proof requests with a name starting with this string.
    pub name: Option<String>,
    /// Filter by one or more country profiles.
    pub profiles: Option<Vec<String>>,
    /// Filter by one or more UUIDs.
    pub ids: Option<Vec<String>>,
    /// Filter by one or more proof request states.
    pub proof_states: Option<Vec<ProofStateBindingEnum>>,
    /// Filter proof requests by one or more roles: requested by the
    /// system (`VERIFIER`) or received by the system (`HOLDER`).
    pub proof_roles: Option<Vec<ProofRoleBindingEnum>>,
    /// Filter by associated proof schemas.
    pub proof_schema_ids: Option<Vec<String>>,
    /// Set which filters apply in an exact way.
    pub exact: Option<Vec<ProofListQueryExactColumnBindingEnum>>,

    /// Return only proof requests created after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_after: Option<String>,
    /// Return only proof requests created before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_before: Option<String>,
    /// Return only proof requests last modified after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub last_modified_after: Option<String>,
    /// Return only proof requests last modified before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub last_modified_before: Option<String>,
    /// Return only proofs requested after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub requested_date_after: Option<String>,
    /// Return only proofs requested before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub requested_date_before: Option<String>,
    /// Return only proofs requested completed after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub completed_date_after: Option<String>,
    /// Return only proofs requested completed before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub completed_date_before: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofListItemResponseDTO)]
#[uniffi(name = "ProofListItem")]
pub struct ProofListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn = optional_time)]
    pub requested_date: Option<String>,
    /// When the wallet holder submitted valid proof.
    #[from(with_fn = optional_time)]
    pub completed_date: Option<String>,
    #[from(with_fn = optional_identifier_id_string)]
    pub verifier: Option<String>,
    /// Protocol used for verification.
    pub protocol: String,
    /// Channel used for this request.
    pub transport: String,
    /// Engagement method used for this request.
    pub engagement: Option<String>,
    /// State representation of this request.
    pub state: ProofStateBindingEnum,
    /// The role the system has in relation to this request.
    pub role: ProofRoleBindingEnum,
    #[from(with_fn = convert_inner)]
    pub schema: Option<GetProofSchemaListItemBindingDTO>,
    /// Time at which the data shared by the wallet holder for this request
    /// will be deleted. Determined by the `expireDuration` parameter of the
    /// proof schema.
    #[from(with_fn = optional_time)]
    pub retain_until_date: Option<String>,
    /// Country profile associated with this request.
    pub profile: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "ProofDetail")]
pub struct ProofResponseBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    /// Identifier of the verifier of this request.
    pub verifier: Option<GetIdentifierListItemBindingDTO>,
    pub state: ProofStateBindingEnum,
    /// The role the system has in relation to this request.
    pub role: ProofRoleBindingEnum,
    /// Schema used for this request.
    pub proof_schema: Option<GetProofSchemaListItemBindingDTO>,
    /// Protocol used for verification.
    pub protocol: String,
    /// Engagement method used for this request.
    pub engagement: Option<String>,
    /// Channel used for this request.
    pub transport: String,
    /// The wallet is redirected to this resource once a shared proof
    /// is accepted.
    pub redirect_uri: Option<String>,
    /// Credential and claim data shared by the wallet holder.
    pub proof_inputs: Vec<ProofInputBindingDTO>,
    /// Time at which the data shared by the wallet holder for this request
    /// will be deleted. Determined by the `expireDuration` parameter of the
    /// proof schema.
    pub retain_until_date: Option<String>,
    /// When the request was shared with the wallet holder.
    pub requested_date: Option<String>,
    /// When the wallet holder submitted valid proof.
    pub completed_date: Option<String>,
    /// When claim data was deleted.
    pub claims_removed_at: Option<String>,
    /// Country profile associated with this request.
    pub profile: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofInputDTO)]
#[uniffi(name = "ProofInput")]
pub struct ProofInputBindingDTO {
    /// Set of claims asserted by the shared credential.
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofRequestClaimBindingDTO>,
    /// Shared credential metadata.
    #[from(with_fn = convert_inner)]
    pub credential: Option<CredentialDetailBindingDTO>,
    /// Credential schema metadata.
    pub credential_schema: CredentialSchemaBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofListResponseDTO)]
#[uniffi(name = "ProofList")]
pub struct ProofListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<ProofListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
#[uniffi(name = "ProofState")]
pub enum ProofStateBindingEnum {
    Created,
    Pending,
    Requested,
    Accepted,
    Rejected,
    Retracted,
    Error,
    InteractionExpired,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(ProofRole)]
#[into(ProofRole)]
#[uniffi(name = "ProofRole")]
pub enum ProofRoleBindingEnum {
    Holder,
    Verifier,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = PresentationSubmitCredentialRequestDTO, Error = ServiceError)]
#[uniffi(name = "PresentationSubmitCredentialRequest")]
pub struct PresentationSubmitCredentialRequestBindingDTO {
    /// ID of the credential to submit.
    #[try_into(with_fn_ref = into_id)]
    pub credential_id: String,
    #[try_into(infallible)]
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = PresentationSubmitV2CredentialRequestDTO, Error = ServiceError)]
#[uniffi(name = "PresentationSubmitV2CredentialRequest")]
pub struct PresentationSubmitV2CredentialRequestBindingDTO {
    /// ID of the credential to submit.
    #[try_into(with_fn_ref = into_id)]
    pub credential_id: String,
    /// Array of claim paths for claims where `userSelection: true` that the
    /// holder chooses to share. Only include paths for optional claims the
    /// holder selects. Omit entirely or use an empty array if withholding all
    /// optional claims.
    #[try_into(infallible)]
    pub user_selections: Vec<String>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ProposeProofRequestDTO, Error = ServiceError)]
#[uniffi(name = "ProposeProofRequest")]
pub struct ProposeProofRequestBindingDTO {
    #[try_into(infallible)]
    pub protocol: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub engagement: Vec<String>,
    #[try_into(infallible)]
    pub ui_message: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProposeProofResponseDTO)]
#[uniffi(name = "ProposeProofResponse")]
pub struct ProposeProofResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub proof_id: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub interaction_id: String,
    pub url: Option<String>,
}

#[derive(Into, uniffi::Record)]
#[into(ShareProofRequestDTO)]
#[uniffi(name = "ShareProofRequest")]
pub struct ShareProofRequestBindingDTO {
    #[into(with_fn = "convert_inner")]
    pub params: Option<ShareProofRequestParamsBindingDTO>,
}

#[derive(Into, uniffi::Record)]
#[into(ShareProofRequestParamsDTO)]
#[uniffi(name = "ShareProofRequestParams")]
pub struct ShareProofRequestParamsBindingDTO {
    /// For requests made with OpenID4VC, a Client ID Scheme can be
    /// specified here. If no scheme is specified the default scheme
    /// from the configuration is used.
    #[into(with_fn = "convert_inner")]
    pub client_id_scheme: Option<ClientIdSchemeBindingEnum>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(ClientIdScheme)]
#[uniffi(name = "ClientIdScheme")]
pub enum ClientIdSchemeBindingEnum {
    RedirectUri,
    VerifierAttestation,
    Did,
    X509SanDns,
}

#[derive(From, uniffi::Record)]
#[from(ShareProofResponseDTO)]
#[uniffi(name = "ShareProofResponse")]
pub struct ShareProofResponseBindingDTO {
    pub url: String,
    #[from(with_fn = optional_time)]
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionResponseDTO)]
#[uniffi(name = "PresentationDefinition")]
pub struct PresentationDefinitionBindingDTO {
    #[from(with_fn = convert_inner)]
    pub request_groups: Vec<PresentationDefinitionRequestGroupBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub credentials: Vec<CredentialDetailBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRequestGroupResponseDTO)]
#[uniffi(name = "PresentationDefinitionRequestGroup")]
pub struct PresentationDefinitionRequestGroupBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub rule: PresentationDefinitionRuleBindingDTO,
    #[from(with_fn = convert_inner)]
    pub requested_credentials: Vec<PresentationDefinitionRequestedCredentialBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "PresentationDefinitionRequestedCredential")]
pub struct PresentationDefinitionRequestedCredentialBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub fields: Vec<PresentationDefinitionFieldBindingDTO>,
    pub applicable_credentials: Vec<String>,
    pub inapplicable_credentials: Vec<String>,
    pub multiple: Option<bool>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "PresentationDefinitionField")]
pub struct PresentationDefinitionFieldBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub purpose: Option<String>,
    pub required: bool,
    pub key_map: HashMap<String, String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(PresentationDefinitionRuleTypeEnum)]
#[uniffi(name = "PresentationDefinitionRuleType")]
pub enum PresentationDefinitionRuleTypeBindingEnum {
    All,
    Pick,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(PresentationDefinitionRuleDTO)]
#[uniffi(name = "PresentationDefinitionRule")]
pub struct PresentationDefinitionRuleBindingDTO {
    pub r#type: PresentationDefinitionRuleTypeBindingEnum,
    pub min: Option<u32>,
    pub max: Option<u32>,
    pub count: Option<u32>,
}

#[derive(Debug, From, uniffi::Record)]
#[from(PresentationDefinitionV2ResponseDTO)]
#[uniffi(name = "PresentationDefinitionV2")]
pub(crate) struct PresentationDefinitionV2ResponseBindingDTO {
    #[from(with_fn = convert_inner)]
    pub credential_queries: HashMap<String, CredentialQueryResponseBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub credential_sets: Vec<CredentialSetResponseBindingDTO>,
}

#[derive(Debug, From, uniffi::Record)]
#[from(CredentialQueryResponseDTO)]
#[uniffi(name = "CredentialQuery")]
pub(crate) struct CredentialQueryResponseBindingDTO {
    pub multiple: bool,
    pub credential_or_failure_hint: ApplicableCredentialOrFailureHintBindingEnum,
}

#[derive(Debug, uniffi::Enum)]
#[allow(clippy::large_enum_variant)]
#[uniffi(name = "ApplicableCredentialOrFailureHint")]
pub(crate) enum ApplicableCredentialOrFailureHintBindingEnum {
    ApplicableCredentials {
        applicable_credentials: Vec<PresentationDefinitionV2CredentialDetailBindingDTO>,
    },
    FailureHint {
        failure_hint: CredentialQueryFailureHintResponseBindingDTO,
    },
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "PresentationDefinitionV2Credential")]
pub struct PresentationDefinitionV2CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
    pub issuer_certificate: Option<CertificateResponseBindingDTO>,
    pub holder: Option<GetIdentifierListItemBindingDTO>,
    pub state: CredentialStateBindingEnum,
    pub schema: CredentialSchemaBindingDTO,
    pub claims: Vec<PresentationDefinitionV2ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    pub role: CredentialRoleBindingDTO,
    pub suspend_end_date: Option<String>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseBindingDTO>,
    pub protocol: String,
    pub profile: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(CredentialDetailClaimExtResponseDTO)]
#[uniffi(name = "PresentationDefinitionV2Claim")]
pub struct PresentationDefinitionV2ClaimBindingDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaBindingDTO,
    pub value: PresentationDefinitionV2ClaimValueBindingDTO,
    pub user_selection: bool,
    pub required: bool,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "PresentationDefinitionV2ClaimValue")]
pub enum PresentationDefinitionV2ClaimValueBindingDTO {
    Boolean {
        value: bool,
    },
    Float {
        value: f64,
    },
    Integer {
        value: i64,
    },
    String {
        value: String,
    },
    Nested {
        value: Vec<PresentationDefinitionV2ClaimBindingDTO>,
    },
}

#[derive(Debug, From, uniffi::Record)]
#[from(CredentialQueryFailureHintResponseDTO)]
#[uniffi(name = "CredentialQueryFailureHint")]
pub(crate) struct CredentialQueryFailureHintResponseBindingDTO {
    pub reason: CredentialQueryFailureReasonBindingEnum,
    #[from(with_fn = "convert_inner")]
    pub credential_schema: Option<CredentialSchemaDetailBindingDTO>,
}

#[derive(Debug, From, uniffi::Enum)]
#[from(CredentialQueryFailureReasonEnum)]
#[uniffi(name = "CredentialQueryFailureReason")]
pub(crate) enum CredentialQueryFailureReasonBindingEnum {
    NoCredential,
    Validity,
    Constraint,
}

#[derive(Debug, From, uniffi::Record)]
#[from(CredentialSetResponseDTO)]
#[uniffi(name = "CredentialSet")]
pub(crate) struct CredentialSetResponseBindingDTO {
    pub required: bool,
    pub options: Vec<Vec<String>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofClaimDTO)]
#[uniffi(name = "ProofClaim")]
pub struct ProofRequestClaimBindingDTO {
    pub schema: ProofClaimSchemaBindingDTO,
    #[from(with_fn = convert_inner)]
    pub value: Option<ProofRequestClaimValueBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "ProofClaimValue")]
pub enum ProofRequestClaimValueBindingDTO {
    Value {
        value: String,
    },
    Claims {
        value: Vec<ProofRequestClaimBindingDTO>,
    },
}
