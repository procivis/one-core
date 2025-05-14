use one_core::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCITxCode, OpenID4VCITxCodeInputMode,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::{From, convert_inner};
use url::Url;

use crate::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn handle_invitation(
        &self,
        url: String,
        organisation_id: String,
        transport: Option<Vec<String>>,
    ) -> Result<HandleInvitationResponseBindingEnum, BindingError> {
        let url = Url::parse(&url).map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        let organisation_id = into_id(&organisation_id)?;

        let core = self.use_core().await?;
        let invitation_response = core
            .ssi_holder_service
            .handle_invitation(url, organisation_id, transport)
            .await?;

        Ok(invitation_response.into())
    }

    #[uniffi::method]
    pub async fn holder_accept_credential(
        &self,
        interaction_id: String,
        did_id: Option<String>,
        identifier_id: Option<String>,
        key_id: Option<String>,
        tx_code: Option<String>,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .accept_credential(
                &into_id(&interaction_id)?,
                did_id.map(into_id).transpose()?,
                identifier_id.map(into_id).transpose()?,
                key_id.map(into_id).transpose()?,
                tx_code,
            )
            .await?)
    }

    #[uniffi::method]
    pub async fn holder_reject_credential(
        &self,
        interaction_id: String,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .ssi_holder_service
            .reject_credential(&into_id(&interaction_id)?)
            .await?)
    }
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum HandleInvitationResponseBindingEnum {
    CredentialIssuance {
        interaction_id: String,
        credential_ids: Vec<String>,
        tx_code: Option<OpenID4VCITxCodeBindingDTO>,
    },
    ProofRequest {
        interaction_id: String,
        proof_id: String,
    },
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(OpenID4VCITxCode)]
pub struct OpenID4VCITxCodeBindingDTO {
    pub input_mode: OpenID4VCITxCodeInputModeBindingEnum,
    #[from(with_fn = convert_inner)]
    pub length: Option<i64>,
    #[from(with_fn = convert_inner)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Enum)]
#[from(OpenID4VCITxCodeInputMode)]
pub enum OpenID4VCITxCodeInputModeBindingEnum {
    Numeric,
    Text,
}
