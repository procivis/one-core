use std::collections::HashMap;

use async_trait::async_trait;
use one_providers::common_dto::PublicKeyJwkDTO;
use one_providers::common_models::credential::Credential;
use one_providers::common_models::did::Did;
use one_providers::common_models::key::{Key, KeyId};
use one_providers::common_models::organisation::Organisation;
use one_providers::common_models::proof::Proof;
use one_providers::credential_formatter::model::DetailCredential;
use one_providers::exchange_protocol::openid4vc::model::{
    DatatypeType, InvitationResponseDTO, OpenID4VPFormat, PresentationDefinitionResponseDTO,
    PresentedCredential, ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use one_providers::exchange_protocol::openid4vc::{
    ExchangeProtocolError, ExchangeProtocolImpl, FormatMapper, HandleInvitationOperationsAccess,
    StorageAccess, TypeToDescriptorMapper,
};
use url::Url;

mod common;
mod device_engagement;
mod session;

pub(crate) struct IsoMdl {}

impl IsoMdl {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ExchangeProtocolImpl for IsoMdl {
    type VCInteractionContext = ();
    type VPInteractionContext = ();

    fn can_handle(&self, _url: &Url) -> bool {
        false
    }

    async fn handle_invitation(
        &self,
        _url: Url,
        _storage_access: &StorageAccess,
        _handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        todo!()
    }

    async fn submit_proof(
        &self,
        _proof: &Proof,
        _credential_presentations: Vec<PresentedCredential>,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        _format_map: HashMap<String, String>,
        _presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        todo!()
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
        _format: &str,
        _storage_access: &StorageAccess,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        unimplemented!()
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
        _credential_format: &str,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn share_proof(
        &self,
        _proof: &Proof,
        _format_to_type_mapper: FormatMapper,
        _key_id: KeyId,
        _encryption_key_jwk: PublicKeyJwkDTO,
        _vp_formats: HashMap<String, OpenID4VPFormat>,
        _type_to_descriptor: TypeToDescriptorMapper,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn get_presentation_definition(
        &self,
        _proof: &Proof,
        _interaction_data: Self::VPInteractionContext,
        _storage_access: &StorageAccess,
        _format_map: HashMap<String, String>,
        _types: HashMap<String, DatatypeType>,
        _organisation: Organisation,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        todo!()
    }

    async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        todo!()
    }
}
