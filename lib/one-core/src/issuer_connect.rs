use crate::model::credential::UpdateCredentialRequest;

use crate::{
    data_model::{ConnectIssuerRequest, ConnectIssuerResponse},
    error::{OneCoreError, SSIError},
    model::did::DidType,
    service::{
        credential::dto::CredentialStateEnum, did::dto::CreateDidRequestDTO, error::ServiceError,
    },
    OneCore,
};

impl OneCore {
    pub async fn issuer_connect(
        &self,
        transport_protocol: &str,
        request: &ConnectIssuerRequest,
    ) -> Result<ConnectIssuerResponse, OneCoreError> {
        // Not used for now
        let _transport = self.get_transport_protocol(transport_protocol)?;

        let credential_id = &request.credential;
        let credential = self
            .credential_service
            .get_credential(credential_id)
            .await
            .map_err(|e| match e {
                ServiceError::NotFound => OneCoreError::SSIError(SSIError::MissingCredential),
                e => OneCoreError::ServiceError(e),
            })?;

        if credential.state != CredentialStateEnum::Offered {
            return Err(OneCoreError::SSIError(SSIError::IncorrectCredentialState));
        }

        let format = &credential.schema.format;

        let formatter = self.get_formatter(format)?;

        let did_id = match self.did_service.get_did_by_value(&request.did).await {
            Ok(did) => did.id,
            Err(ServiceError::NotFound) => {
                self.did_service
                    .create_did(CreateDidRequestDTO {
                        name: "TODO".to_string(),
                        organisation_id: credential.schema.organisation_id,
                        did: request.did.clone(),
                        did_method: "KEY".to_string(),
                        did_type: DidType::Remote,
                    })
                    .await?
            }
            Err(e) => {
                return Err(OneCoreError::ServiceError(e));
            }
        };

        let token = formatter
            .format_credentials(&credential, &request.did)
            .map_err(OneCoreError::FormatterError)?;

        self.credential_repository
            .update_credential(UpdateCredentialRequest {
                id: credential_id.to_owned(),
                credential: Some(token.bytes().collect()),
                holder_did_id: Some(did_id.to_owned()),
                state: None,
            })
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(ConnectIssuerResponse {
            credential: token,
            format: format.to_owned(),
        })
    }
}
