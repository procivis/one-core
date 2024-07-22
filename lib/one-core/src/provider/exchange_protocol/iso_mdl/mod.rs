use async_trait::async_trait;
use one_providers::common_models::key::Key;
use one_providers::credential_formatter::model::DetailCredential;
use url::Url;

use super::dto::{ShareResponse, UpdateResponse};
use super::StorageAccess;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::exchange_protocol::dto::{
    PresentationDefinitionResponseDTO, PresentedCredential, SubmitIssuerResponse,
};
use crate::provider::exchange_protocol::{ExchangeProtocolError, ExchangeProtocolImpl};
use crate::service::ssi_holder::dto::InvitationResponseDTO;

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
        _organisation: Organisation,
        _storage_access: &StorageAccess,
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
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        todo!()
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
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
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn share_proof(
        &self,
        _proof: &Proof,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        unimplemented!()
    }

    async fn get_presentation_definition(
        &self,
        _proof: &Proof,
        _interaction_data: Self::VPInteractionContext,
        _storage_access: &StorageAccess,
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
