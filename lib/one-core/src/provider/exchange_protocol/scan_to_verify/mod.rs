use async_trait::async_trait;
use one_providers::common_models::key::Key;
use url::Url;

use super::dto::ShareResponse;
use crate::model::credential::Credential;
use crate::model::did::Did;
use crate::model::organisation::Organisation;
use crate::model::proof::Proof;
use crate::provider::exchange_protocol::dto::{
    PresentationDefinitionResponseDTO, PresentedCredential, SubmitIssuerResponse,
};
use crate::provider::exchange_protocol::{ExchangeProtocolError, ExchangeProtocolImpl};
use crate::service::ssi_holder::dto::InvitationResponseDTO;

pub(crate) struct ScanToVerify {}

impl ScanToVerify {
    #[allow(clippy::too_many_arguments)]
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl ExchangeProtocolImpl for ScanToVerify {
    type VCInteractionContext = ();
    type VPInteractionContext = ();

    fn can_handle(&self, _url: &Url) -> bool {
        todo!()
    }

    async fn handle_invitation(
        &self,
        _url: Url,
        _organisation: Organisation,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        todo!()
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
    ) -> Result<(), ExchangeProtocolError> {
        todo!()
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
        _holder_did: &Did,
        _key: &Key,
        _jwk_key_id: Option<String>,
    ) -> Result<SubmitIssuerResponse, ExchangeProtocolError> {
        todo!()
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        todo!()
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
    ) -> Result<ShareResponse<Self::VCInteractionContext>, ExchangeProtocolError> {
        todo!()
    }

    async fn share_proof(
        &self,
        _proof: &Proof,
    ) -> Result<ShareResponse<Self::VPInteractionContext>, ExchangeProtocolError> {
        todo!()
    }

    async fn get_presentation_definition(
        &self,
        _proof: &Proof,
    ) -> Result<PresentationDefinitionResponseDTO, ExchangeProtocolError> {
        todo!()
    }
}
