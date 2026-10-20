use std::collections::HashMap;

use one_core::model::proof::{
    ExactProofFilterColumn, ProofRole, ProofStateEnum, SortableProofColumn,
};
use one_core::provider::transaction_data::{
    TransactionDataDisplayAttribute, TransactionDataDisplayValue,
};
use one_core::provider::verification_protocol::dto::{
    CredentialDetailClaimExtResponseDTO, CredentialQueryFailureHintResponseDTO,
    CredentialQueryFailureReasonEnum, CredentialQueryResponseDTO, CredentialSetResponseDTO,
    DisclosurePolicyViolation, PresentationDefinitionTransactionDataDTO,
    PresentationDefinitionV2ResponseDTO,
};
use one_core::service::credential_schema::dto::CredentialSchemaDetailResponseDTO;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::{
    GetProofListResponseDTO, ProofClaimDTO, ProofInputDTO, ProofListItemResponseDTO,
    ProofTransactionDataResponseDTO, ProposeProofRequestDTO, ProposeProofResponseDTO,
    ShareProofRequestDTO, ShareProofRequestParamsDTO, ShareProofResponseDTO,
};
use one_core::service::ssi_holder::dto::PresentationSubmitV2RequestDTO;
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner_of_inner};
use standardized_types::openid4vp::ClientIdPrefix;

use super::common::SortDirection;
use super::credential::{
    CredentialDetailBindingDTO, CredentialRoleBindingDTO, CredentialStateBindingEnum,
    MdocMsoValidityResponseBindingDTO, TrustInformationBindingDTO,
};
use super::identifier::{CertificateResponseBindingDTO, GetIdentifierListItemBindingDTO};
use super::mapper::{optional_identifier_id_string, optional_time};
use super::proof_schema::{GetProofSchemaListItemBindingDTO, ProofClaimSchemaBindingDTO};
use crate::OneCore;
use crate::binding::credential::{CredentialClaimSchemaBindingDTO, CredentialSchemaBindingDTO};
use crate::binding::credential_schema::{
    CredentialSchemaLayoutPropertiesBindingDTO, CredentialSchemaTransactionCodeBindingDTO,
    CredentialSchemaTranslationsBindingDTO, KeyStorageSecurityBindingEnum,
};
use crate::binding::trust_information::TrustInformationDetailResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// For verifiers, creates a proof request and returns its ID. Choose
    /// what information to request via a proof schema, an identifier, and
    /// which protocol to use for making the request.
    ///
    /// For online protocols, the request is created in `CREATED` state;
    /// share it with the wallet using `shareProof`. For `ISO_MDL`, the
    /// wallet starts the exchange: pass the device engagement data from the
    /// wallet in `isoMdlEngagement`. The request is created directly in
    /// `PENDING` state and needs no sharing.
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
    ///
    /// Poll this method to follow the state of the request.
    #[uniffi::method]
    pub async fn get_proof(
        &self,
        proof_id: String,
    ) -> Result<ProofResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let proof = core.proof_service.get_proof(&into_id(&proof_id)?).await?;
        Ok(proof.into())
    }

    /// Returns detailed trust information about the requesting entity for a
    /// proof request.
    #[uniffi::method]
    pub async fn get_proof_trust_information(
        &self,
        proof_id: String,
    ) -> Result<TrustInformationDetailResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let trust_information = core
            .proof_service
            .get_trust_details(into_id(&proof_id)?)
            .await?;
        Ok(trust_information.into())
    }

    /// Deletes an incomplete proof request. If the request is in `REQUESTED`
    /// state the proof is retracted instead, retaining history of the interaction.
    ///
    /// For `ISO_MDL`, this also closes the BLE session.
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
        let proofs = core.proof_service.get_proof_list(query.try_into()?).await?;
        Ok(proofs.into())
    }

    /// For wallets, rejects a proof request. Pass the `interactionId` of
    /// the request, not the proof ID.
    ///
    /// For `ISO_MDL`, the wallet sends an empty response to the verifier and
    /// closes the BLE session.
    #[uniffi::method]
    pub async fn holder_reject_proof(&self, interaction_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .reject_proof_request(&into_id(&interaction_id)?)
            .await?)
    }

    /// For wallets, submits a presentation using DCQL as a query language.
    /// Use this after `getPresentationDefinitionV2`. Pass the
    /// `interactionId` of the request, not the proof ID.
    ///
    /// `submission` maps each credential query ID from the presentation
    /// definition to the credentials chosen for it.
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
    ///
    /// For `ISO_MDL`, this creates a proof in `PENDING` state and starts BLE
    /// according to the `bleMode` set in your configuration. Poll `getProof`
    /// until the state is `REQUESTED`, then call
    /// `getPresentationDefinitionV2`.
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
    /// URL to access the request. Not used for the `ISO_MDL` proximity flow.
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

    /// Deletes the claim data shared by the wallet holder for a proof
    /// request, without waiting for the retention period set by the
    /// `expireDuration` of the proof schema. The proof request itself is
    /// kept, and `claimsRemovedAt` records when the claims were deleted.
    #[uniffi::method]
    pub async fn delete_proof_claims(&self, proof_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        core.proof_service
            .delete_proof_claims(into_id(&proof_id)?)
            .await?;
        Ok(())
    }

    /// For wallets, returns what a proof request asks for and which of the
    /// wallet's credentials can satisfy it. Use the result to build the
    /// submission for `holderSubmitProofV2`.
    ///
    /// For `ISO_MDL` requests, every claim has `required: false`, since the
    /// protocol cannot mark claims as mandatory. An incomplete submission
    /// may be rejected if the verifier requires claims not submitted.
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

    /// For wallets; returns the details of a single transaction data entry of a
    /// proof request, including human-readable display data and the raw
    /// transaction data received from the verifier. The `transactionDataId` is
    /// obtained from `getPresentationDefinitionV2`. See
    /// [Transaction Authorization for Wallets](https://docs.procivis.ch/hold/transaction-authorization)
    /// for more information.
    #[uniffi::method]
    pub async fn holder_get_transaction_data(
        &self,
        proof_id: String,
        transaction_data_id: String,
    ) -> Result<ProofTransactionDataResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .proof_service
            .holder_transaction_data_details(&into_id(&proof_id)?, &into_id(&transaction_data_id)?)
            .await?
            .into())
    }
}

/// If `protocol` is `ISO_MDL`, also set `engagement`, `isoMdlEngagement`,
/// and `transport`.
#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateProofRequest")]
pub struct CreateProofRequestBindingDTO {
    /// Choose a proof schema to use.
    pub proof_schema_id: String,
    /// Deprecated. Use `verifierIdentifierId`.
    pub verifier_did_id: Option<String>,
    /// Choose the identifier to use to make the request. Either this or
    /// the deprecated `verifierDidId` must be set.
    ///
    /// For `ISO_MDL`, a certificate identifier enables reader
    /// authentication, so the wallet can verify who is asking. Key
    /// identifiers are not allowed.
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
    /// specify which certificate to use. If omitted, the first suitable
    /// certificate is used.
    pub verifier_certificate: Option<String>,
    /// For `ISO_MDL`, the device engagement data received from the
    /// wallet: the scanned QR code content, or the result of
    /// `nfcReadIsoMdlEngagement`.
    pub iso_mdl_engagement: Option<String>,
    /// Choose the transport protocol for the exchange. Check the
    /// `transport` object of your configuration for supported
    /// options and reference the configuration instance. For
    /// `ISO_MDL`, use `BLE`.
    pub transport: Option<Vec<String>>,
    /// Country profile to associate with this request. See
    /// [Country Profiles](https://docs.procivis.ch/profiles) for more
    /// information.
    pub profile: Option<String>,
    /// For `ISO_MDL`, the device engagement method used to receive
    /// `isoMdlEngagement`, such as `NFC` or `QR_CODE`. Reference an
    /// entry from the `verificationEngagement` object of your configuration.
    pub engagement: Option<String>,
    /// Optional transaction data to request authorization for. Only
    /// supported for OpenID4VP. See
    /// [Transaction Authorization for Verifiers](https://docs.procivis.ch/verify/transaction-authorization)
    /// for more information.
    pub transaction_data: Option<Vec<ProofRequestTransactionDataBindingDTO>>,
    /// Use this to enforce the constraints of a regulatory ecosystem
    /// for this request. See
    /// [Enforcing an Ecosystem as a Verifier](https://docs.procivis.ch/verify/ecosystem-enforcement)
    /// for more information.
    pub ecosystem: Option<String>,
}

/// Transaction data to include in a proof request.
#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "ProofRequestTransactionData")]
pub struct ProofRequestTransactionDataBindingDTO {
    /// The transaction data provider to use.
    pub r#type: String,
    /// The credential schemas (of the given proof schema) the transaction data
    /// applies to.
    pub credential_schema_ids: Vec<String>,
    /// Type-specific transaction data content, encoded as a JSON string.
    pub data: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactProofFilterColumn)]
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
    /// Filter by one or more country profiles. See
    /// [Country Profiles](https://docs.procivis.ch/profiles) for more
    /// information.
    pub profiles: Option<Vec<String>>,
    /// Filter by ecosystem applied to proof. See
    /// [Ecosystems](https://docs.procivis.ch/ecosystems)
    /// for more information.
    pub ecosystems: Option<Vec<String>>,
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
    /// Return only proofs completed after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub completed_date_after: Option<String>,
    /// Return only proofs completed before this time. Timestamp in
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
    /// Country profile associated with this request. See
    /// [Country Profiles](https://docs.procivis.ch/profiles) for more
    /// information.
    pub profile: Option<String>,
    /// Ecosystem applied to this request. See
    /// [Ecosystems](https://docs.procivis.ch/ecosystems)
    /// for more information.
    #[from(with_fn = convert_inner)]
    pub ecosystem: Option<String>,
    pub redirect_uri: Option<String>,
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
    /// Country profile associated with this request. See
    /// [Country Profiles](https://docs.procivis.ch/profiles) for more
    /// information.
    pub profile: Option<String>,
    /// Trust information of the verifier, if any.
    pub trust_information: Option<TrustInformationBindingDTO>,
    /// Transaction data attached to this proof request. Present only if the proof
    /// role is `VERIFIER`. See
    /// [Transaction Authorization for Verifiers](https://docs.procivis.ch/verify/transaction-authorization)
    /// for more information.
    pub transaction_data: Option<Vec<TransactionDataResponseBindingDTO>>,
    /// Ecosystem applied to this request. See
    /// [Ecosystems](https://docs.procivis.ch/ecosystems)
    /// for more information.
    pub ecosystem: Option<String>,
}

/// Transaction data attached to a proof request.
#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "TransactionDataResponse")]
pub struct TransactionDataResponseBindingDTO {
    /// The transaction data provider used.
    pub r#type: String,
    /// The credential schemas the transaction data applies to.
    pub credential_schema_ids: Vec<String>,
    /// Type-specific transaction data content, encoded as a JSON string.
    pub data: Option<String>,
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
    /// Trust of the credential shared for this input, and of its issuer.
    #[from(with_fn = convert_inner)]
    pub trust_information: Option<TrustInformationBindingDTO>,
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

/// State of a proof request. Some states mean something different
/// depending on whether the system is the holder or the verifier of the
/// request. See [Proof States as a Verifier](https://docs.procivis.ch/verify/states)
/// and [Proof States as a Holder](https://docs.procivis.ch/hold/manage-credentials-requests#proof-request-states-as-a-holder)
/// for complete state diagrams.
#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(ProofStateEnum)]
#[into(ProofStateEnum)]
#[uniffi(name = "ProofState")]
pub enum ProofStateBindingEnum {
    /// For verifiers, the request was created but not yet shared with a
    /// wallet.
    Created,
    /// Waiting for the other party. For verifiers, the request was shared
    /// or, for `ISO_MDL`, created from the wallet's engagement data. For
    /// holders, device engagement was started with `proposeProof`.
    Pending,
    /// The request reached the wallet and is waiting for the holder to
    /// respond.
    Requested,
    /// For verifiers, the presentation was received and verified. For
    /// holders, the presentation was submitted.
    Accepted,
    /// The holder rejected the request. Not all protocols report a
    /// rejection to the verifier.
    Rejected,
    /// The request was cancelled with `deleteProof` after it reached
    /// `REQUESTED`. The history of the interaction is retained.
    Retracted,
    /// A technical error occurred or, for verifiers, the presentation
    /// could not be verified.
    Error,
    /// For verifiers, the shared request expired before a wallet
    /// connected. Share it again with `shareProof`.
    InteractionExpired,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(ProofRole)]
#[into(ProofRole)]
#[uniffi(name = "ProofRole")]
pub enum ProofRoleBindingEnum {
    /// The system received this request.
    Holder,
    /// The system made this request.
    Verifier,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "PresentationSubmitV2CredentialRequest")]
pub struct PresentationSubmitV2CredentialRequestBindingDTO {
    /// ID of the credential to submit.
    pub credential_id: String,
    /// Array of claim paths for claims where `userSelection: true` that the
    /// holder chooses to share. Only include paths for optional claims the
    /// holder selects. Omit entirely or use an empty array if withholding all
    /// optional claims.
    pub user_selections: Option<Vec<String>>,
    /// Optional ids of transaction-data entries to bind to this credential.
    /// Entries not listed here are auto-assigned. IDs must reference transaction
    /// data applicable to this credential. Omit entirely or use an empty array
    /// to auto-assign all transaction data. See
    /// [Transaction Authorization for Wallets](https://docs.procivis.ch/hold/transaction-authorization)
    /// for more information.
    pub transaction_data_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ProposeProofRequestDTO, Error = ServiceError)]
#[uniffi(name = "ProposeProofRequest")]
pub struct ProposeProofRequestBindingDTO {
    /// Choose the protocol to use. Check the `verificationProtocol`
    /// object of your configuration for supported options and reference
    /// the configuration instance.
    #[try_into(infallible)]
    pub protocol: String,
    /// Specifies the organizational context for this operation.
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    /// The device engagement method to offer. Reference one or more entries
    /// from the `verificationEngagement` object of your configuration.
    #[try_into(infallible)]
    pub engagement: Vec<String>,
    /// Text shown on the iOS system overlay during NFC engagement. Has
    /// no effect for QR code engagement or on Android.
    #[try_into(infallible)]
    pub ui_message: Option<String>,
    /// Use this to enforce the constraints of a regulatory ecosystem
    /// for this presentation. See
    /// [Enforcing an Ecosystem as a Wallet](https://docs.procivis.ch/hold/ecosystem-enforcement)
    /// for more information.
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProposeProofResponseDTO)]
#[uniffi(name = "ProposeProofResponse")]
pub struct ProposeProofResponseBindingDTO {
    /// ID of the proof, created in `PENDING` state. Use it with
    /// `getProof` and `getPresentationDefinitionV2`.
    #[from(with_fn_ref = "ToString::to_string")]
    pub proof_id: String,
    /// Use with `holderSubmitProofV2` and `holderRejectProof`.
    #[from(with_fn_ref = "ToString::to_string")]
    pub interaction_id: String,
    /// For QR code engagement, the device engagement data to display as a
    /// QR code. Not returned for NFC engagement.
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

#[derive(Clone, Debug, uniffi::Enum, Into)]
#[uniffi(name = "ClientIdScheme")]
#[into(ClientIdPrefix)]
pub enum ClientIdSchemeBindingEnum {
    RedirectUri,
    VerifierAttestation,
    DecentralizedIdentifier,
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

/// What a proof request asks for, together with the wallet's credentials
/// that can satisfy it.
#[derive(Debug, From, uniffi::Record)]
#[from(PresentationDefinitionV2ResponseDTO)]
#[uniffi(name = "PresentationDefinitionV2")]
pub(crate) struct PresentationDefinitionV2ResponseBindingDTO {
    /// One entry per requested credential, keyed by credential query ID.
    /// Use these IDs as the keys of the submission for
    /// `holderSubmitProofV2`.
    #[from(with_fn = convert_inner)]
    pub credential_queries: HashMap<String, CredentialQueryResponseBindingDTO>,
    /// Combinations of credential queries that satisfy the request.
    #[from(with_fn = convert_inner)]
    pub credential_sets: Vec<CredentialSetResponseBindingDTO>,
    /// Transaction data entries attached to the request. Get the details
    /// of an entry with `holderGetTransactionData`.
    #[from(with_fn = convert_inner)]
    pub transaction_data: Vec<PresentationDefinitionTransactionDataBindingDTO>,
}

#[derive(Debug, From, uniffi::Record)]
#[from(PresentationDefinitionTransactionDataDTO)]
#[uniffi(name = "PresentationDefinitionTransactionData")]
pub(crate) struct PresentationDefinitionTransactionDataBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub r#type: String,
    #[from(with_fn = convert_inner)]
    pub credential_query_ids: Vec<String>,
}

/// Details of a single (holder-side) transaction data entry of a proof request.
#[derive(Debug, From, uniffi::Record)]
#[from(ProofTransactionDataResponseDTO)]
#[uniffi(name = "ProofTransactionData")]
pub(crate) struct ProofTransactionDataResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    /// The transaction data provider that validated this entry.
    #[from(with_fn_ref = "ToString::to_string")]
    pub r#type: String,
    /// Credential query ids the transaction data is bound to.
    #[from(with_fn = convert_inner)]
    pub credential_query_ids: Vec<String>,
    /// Grouped key-value data for displaying the transaction to the user.
    #[from(with_fn = convert_inner)]
    pub transaction_data_display: Vec<TransactionDataDisplayBindingDTO>,
    /// The raw transaction data received from the verifier, encoded as a JSON
    /// string.
    #[from(with_fn = inner_to_string)]
    pub raw_transaction_data: Option<String>,
}

#[derive(Debug, From, uniffi::Record)]
#[from(TransactionDataDisplayValue)]
#[uniffi(name = "TransactionDataDisplay")]
pub(crate) struct TransactionDataDisplayBindingDTO {
    pub title: Option<String>,
    #[from(with_fn = convert_inner)]
    pub attributes: Vec<TransactionDataDisplayAttributeBindingDTO>,
}

#[derive(Debug, From, uniffi::Record)]
#[from(TransactionDataDisplayAttribute)]
#[uniffi(name = "TransactionDataDisplayAttribute")]
pub(crate) struct TransactionDataDisplayAttributeBindingDTO {
    pub key: String,
    pub value: String,
}

#[derive(Debug, From, uniffi::Record)]
#[from(CredentialQueryResponseDTO)]
#[uniffi(name = "CredentialQuery")]
pub(crate) struct CredentialQueryResponseBindingDTO {
    /// Whether more than one credential can be submitted for this query.
    pub multiple: bool,
    /// Either the wallet's credentials that match this query, or the
    /// reason no credential matches.
    pub credential_or_failure_hint: ApplicableCredentialOrFailureHintBindingEnum,
}

#[derive(Debug, uniffi::Enum)]
#[allow(clippy::large_enum_variant)]
#[uniffi(name = "ApplicableCredentialOrFailureHint")]
pub(crate) enum ApplicableCredentialOrFailureHintBindingEnum {
    /// The wallet's credentials that match the query.
    ApplicableCredentials {
        applicable_credentials: Vec<PresentationDefinitionV2CredentialDetailBindingDTO>,
        purpose: Option<HashMap<String, String>>,
    },
    /// Why no credential in the wallet matches the query.
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
    pub format: Option<String>,
    /// Present when the relying party's certificates do not satisfy
    /// the embedded disclosure policy attached to the requested
    /// credential. The wallet should surface this to the user as a
    /// warning before they proceed with disclosure. See
    /// [Handling Trust Information](https://docs.procivis.ch/wallet/handling-trust).
    pub embedded_disclosure_policy_violation: Option<DisclosurePolicyViolationBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(DisclosurePolicyViolation)]
#[uniffi(name = "DisclosurePolicyViolation")]
pub struct DisclosurePolicyViolationBindingDTO {
    pub id: String,
    pub description: Option<String>,
    pub url: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(CredentialDetailClaimExtResponseDTO)]
#[uniffi(name = "PresentationDefinitionV2Claim")]
pub struct PresentationDefinitionV2ClaimBindingDTO {
    /// Path of the claim. Use it in `userSelections` when submitting.
    pub path: String,
    pub schema: CredentialClaimSchemaBindingDTO,
    pub value: PresentationDefinitionV2ClaimValueBindingDTO,
    /// Whether the holder can choose whether to share this claim. To
    /// share it, include its `path` in `userSelections` when submitting.
    pub user_selection: bool,
    /// Whether the verifier marked this claim as required. Always
    /// `false` for `ISO_MDL` requests.
    pub required: bool,
    /// Whether the ecosystem requires user consent before this biometric
    /// claim is shared.
    pub require_biometric_data_user_consent: bool,
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaDetailResponseDTO)]
#[uniffi(name = "CredentialSchemaDetailInfo")]
pub struct CredentialSchemaDetailBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub format: String,
    #[from(with_fn = inner_to_string)]
    pub revocation_method: Option<String>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
    #[from(with_fn = convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeBindingDTO>,
    pub translations: CredentialSchemaTranslationsBindingDTO,
}

fn inner_to_string(value: Option<impl ToString>) -> Option<String> {
    value.map(|inner| inner.to_string())
}

#[derive(Debug, From, uniffi::Enum)]
#[from(CredentialQueryFailureReasonEnum)]
#[uniffi(name = "CredentialQueryFailureReason")]
pub(crate) enum CredentialQueryFailureReasonBindingEnum {
    /// The wallet holds no credential of the requested type.
    NoCredential,
    /// Credentials of the requested type exist, but none is currently
    /// valid.
    Validity,
    /// Credentials of the requested type exist, but none satisfies the
    /// constraints of the request.
    Constraint,
}

#[derive(Debug, From, uniffi::Record)]
#[from(CredentialSetResponseDTO)]
#[uniffi(name = "CredentialSet")]
pub(crate) struct CredentialSetResponseBindingDTO {
    /// Whether this set must be satisfied for the request to be
    /// satisfied.
    pub required: bool,
    /// Alternative combinations of credential query IDs. Satisfying any
    /// one combination satisfies the set.
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
