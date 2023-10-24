use super::{
    dto::{InvitationResponse, InvitationType, SubmitIssuerResponse},
    TransportProtocol, TransportProtocolError,
};
use crate::model::{credential::Credential, did::Did, proof::Proof};
use async_trait::async_trait;

#[derive(Default)]
pub struct OpenID4VC {}
#[async_trait]
impl TransportProtocol for OpenID4VC {
    fn detect_invitation_type(&self, _url: &str) -> Option<InvitationType> {
        unimplemented!()
    }

    async fn handle_invitation(
        &self,
        _url: &str,
        _own_did: &Did,
    ) -> Result<InvitationResponse, TransportProtocolError> {
        unimplemented!()
    }

    async fn reject_proof(&self, _proof: &Proof) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn submit_proof(
        &self,
        _proof: &Proof,
        _presentation: &str,
    ) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn accept_credential(
        &self,
        _credential: &Credential,
    ) -> Result<SubmitIssuerResponse, TransportProtocolError> {
        unimplemented!()
    }

    async fn reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), TransportProtocolError> {
        unimplemented!()
    }

    async fn share_credential(
        &self,
        _credential: &Credential,
    ) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }

    async fn share_proof(&self, _proof: &Proof) -> Result<String, TransportProtocolError> {
        unimplemented!()
    }
}
