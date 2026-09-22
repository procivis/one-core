use std::collections::HashMap;

use one_core::model::interaction::InteractionType;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::{ProposeProofRequestDTO, ProposeProofResponseDTO};
use one_core::service::ssi_holder::dto::{
    ContinueIssuanceResponseDTO, HandleInvitationRequestDTO, InitiateIssuanceResponseDTO,
    IssuanceAcceptResponseDTO, PresentationSubmitV2CredentialRequestDTO,
    PresentationSubmitV2RequestDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, DidId, EcosystemId, IdentifierId, InstanceId, InteractionId, KeyId,
    OrganisationId, ProofId, TransactionDataId,
};
use standardized_types::openid4vci::{AuthorizationDetail, TxCode, TxCodeInputMode};
use strum::Display;
use url::Url;
use utoipa::ToSchema;

use crate::dto::common::ecosystem::EcosystemOutcomesRestDTO;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::credential_schema::dto::KeyStorageSecurityRestEnum;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, ModifySchema, TryInto)]
#[try_into(T = HandleInvitationRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HandleInvitationRequestRestDTO {
    #[schema(example = "https://example.com/credential-offer")]
    #[try_into(infallible)]
    /// Typically encoded as a QR code or deep link by the issuer or verifier.
    pub url: Url,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[schema(example = json!(["HTTP"]))]
    /// For configurations with multiple transport protocols enabled you can
    /// specify which one to use for this interaction.
    #[modify_schema(field = transport)]
    #[schema(nullable = false)]
    #[try_into(infallible)]
    pub transport: Option<Vec<String>>,
    /// For issuer-initiated Authorization Code Flow, provide the authorization server
    /// with the URI it should return the user to once authorization is complete.
    #[try_into(infallible)]
    pub redirect_uri: Option<String>,
    #[modify_schema(field = ecosystem)]
    #[schema(nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandleInvitationResponseRestDTO {
    /// One entry per ecosystem provider consulted. Empty when the organisation has no
    /// ecosystem selected.
    pub ecosystem_errors: EcosystemOutcomesRestDTO,
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionTypeRestEnum,
    /// Requested proof.
    pub proof_id: Option<ProofId>,
    /// Metadata for entering a transaction code.
    /// If a pre-authorized code is issued with a transaction code object, the
    /// wallet user must input a transaction code to receive the offered credential.
    /// This code is typically sent through a separate channel such as SMS or email.
    pub tx_code: Option<OpenID4VCITxCodeRestDTO>,
    /// For issuer-initiated Authorization Code Flows, use this URL to start the
    /// authorization process with the authorization server.
    pub authorization_code_flow_url: Option<String>,
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurityRestEnum>>,
    pub key_algorithms: Option<Vec<String>>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub protocol: Option<String>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(InteractionType)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum InteractionTypeRestEnum {
    Issuance,
    Verification,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ContinueIssuanceResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ContinueIssuanceResponseRestDTO {
    /// For reference.
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionTypeRestEnum,
    #[from(with_fn = convert_inner_of_inner)]
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurityRestEnum>>,
    pub key_algorithms: Option<Vec<String>>,
    pub requires_wallet_instance_attestation: bool,
    pub protocol: String,
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[derive(Clone, Serialize, Debug, From, ToSchema)]
#[from(TxCode)]
pub(crate) struct OpenID4VCITxCodeRestDTO {
    #[schema(value_type = String, example = "numeric", default = "numeric")]
    #[serde(default)] // we always provide it, but it is optional according to OpenID4VCI standard
    /// Type of code expected.
    pub input_mode: OpenID4VCITxCodeInputModeRestDTO,
    /// Length of transaction code, to pass to the frontend for guiding the
    /// wallet holder.
    pub length: Option<i64>,
    #[schema(value_type = String, example = "Pin number", max_length = 300)]
    /// Information about the transaction code, to pass to the frontend for
    /// guiding the wallet holder.
    pub description: Option<String>,
}

#[derive(Clone, Serialize, Debug, PartialEq, Display, From, Default)]
#[from(TxCodeInputMode)]
pub(crate) enum OpenID4VCITxCodeInputModeRestDTO {
    #[serde(rename = "numeric")]
    #[strum(serialize = "numeric")]
    #[default]
    Numeric,
    #[serde(rename = "text")]
    #[strum(serialize = "text")]
    Text,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssuanceAcceptRequestRestDTO {
    /// The identifier associated with the particular issuance.
    pub interaction_id: InteractionId,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    /// If you are using a DID and it supports multiple keys for authentication,
    /// specify which key to use. If no key is specified the first suitable key listed
    /// will be used.
    pub key_id: Option<KeyId>,
    pub tx_code: Option<String>,
    #[schema(deprecated = true, nullable = false, value_type = Option<Uuid>)]
    #[expect(unused)]
    /// Deprecated. The holder wallet instance registered for the linked organisation is used
    pub holder_wallet_unit_id: Option<InstanceId>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct IssuanceRefreshResponseRestDTO {
    pub ids: Vec<CredentialId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IssuanceRejectRequestRestDTO {
    pub interaction_id: InteractionId,
    /// Credentials or batch items to reject. Selecting a batch parent rejects all its items.
    /// If not specified, all credentials of the interaction are rejected.
    /// A batch format is notified as rejected and excluded from refreshes only when all its
    /// items are rejected.
    pub credential_ids: Option<Vec<CredentialId>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(IssuanceAcceptResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssuanceAcceptResponseRestDTO {
    /// One entry per ecosystem provider consulted. Empty when the organisation has no
    /// ecosystem selected.
    pub ecosystem_errors: EcosystemOutcomesRestDTO,
    /// Deprecated. Use `credentialIds`.
    #[schema(deprecated = true)]
    pub id: CredentialId,
    /// One credential per accepted credential configuration.
    pub credential_ids: Vec<CredentialId>,
    /// Some of the offered credential configurations could not be issued.
    /// Only present when several configurations were offered.
    pub partially_successful: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PresentationRejectRequestRestDTO {
    /// The identifier associated with a particular verification interaction.
    pub interaction_id: InteractionId,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum SingleOrArray<T> {
    Single(T),
    Array(Vec<T>),
}

impl<T> From<SingleOrArray<T>> for Vec<T> {
    fn from(value: SingleOrArray<T>) -> Self {
        match value {
            SingleOrArray::Single(v) => vec![v],
            SingleOrArray::Array(v) => v,
        }
    }
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(PresentationSubmitV2RequestDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PresentationSubmitV2RequestRestDTO {
    pub interaction_id: InteractionId,
    #[into(with_fn = convert_inner_of_inner)]
    #[serde(deserialize_with = "deserialize_credential_submission")]
    pub submission: HashMap<String, Vec<PresentationSubmitV2CredentialRequestRestDTO>>,
}

fn deserialize_credential_submission<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<PresentationSubmitV2CredentialRequestRestDTO>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map =
        HashMap::<String, SingleOrArray<PresentationSubmitV2CredentialRequestRestDTO>>::deserialize(
            deserializer,
        )?;
    Ok(map.into_iter().map(|(k, v)| (k, v.into())).collect())
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(PresentationSubmitV2CredentialRequestDTO)]
pub(crate) struct PresentationSubmitV2CredentialRequestRestDTO {
    /// Applicable credential or batch parent ID. Batch items need not appear in the
    /// presentation definition, but must be valid, unconsumed, and match the query.
    /// For a parent, the core selects any available item matching the query.
    pub credential_id: CredentialId,
    /// Path of claims that were optionally selected by the user.
    #[serde(default)]
    pub user_selections: Vec<String>,
    /// Optional ids of transaction-data entries to be included in the presentation of this credential.
    /// Entries not listed here are auto-assigned. Ids must reference transaction
    /// data applicable to this credential.
    #[serde(default)]
    pub transaction_data_ids: Vec<TransactionDataId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, ModifySchema, TryInto)]
#[try_into(T = ProposeProofRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProposeProofRequestRestDTO {
    #[try_into(infallible)]
    pub protocol: String,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(infallible)]
    pub engagement: Vec<String>,
    #[try_into(infallible)]
    pub ui_message: Option<String>,
    #[modify_schema(field = ecosystem)]
    #[schema(nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ProposeProofResponseDTO)]
pub(crate) struct ProposeProofResponseRestDTO {
    pub proof_id: ProofId,
    pub interaction_id: InteractionId,
    pub url: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InitiateIssuanceRequestRestDTO {
    /// Organization to place the issued credential into.
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    pub organisation_id: Option<OrganisationId>,
    /// Selected issuance protocol.
    pub protocol: String,
    /// OpenID4VCI authorization request parameter.
    pub issuer: String,
    /// OpenID4VCI authorization request parameter.
    pub client_id: String,
    /// OpenID4VCI authorization request parameter.
    pub redirect_uri: Option<String>,
    /// OpenID4VCI authorization request parameter.
    pub scope: Option<Vec<String>>,
    /// OpenID4VCI authorization request parameter.
    pub authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailRestDTO>>,

    #[modify_schema(field = ecosystem)]
    #[schema(nullable = false)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(AuthorizationDetail)]
#[serde(rename_all = "camelCase")]
// > Additional authorization_details data fields MAY be defined and used
// > when the type value is openid_credential. Note that this effectively
// > defines an authorization details type that is never considered invalid
// > due to unknown fields.
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1-4
pub(crate) struct InitiateIssuanceAuthorizationDetailRestDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(InitiateIssuanceResponseDTO)]
pub(crate) struct InitiateIssuanceResponseRestDTO {
    /// Authorization endpoint URL
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ContinueIssuanceRequestRestDTO {
    #[schema(example = "myapp://example/credential-offer?code=xxx&clientId=myWallet&...")]
    /// Starts with the `redirectUri` and is used to continue the
    /// Authorization Code Flow issuance process.
    pub url: String,
}
