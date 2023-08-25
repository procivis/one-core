use std::str::FromStr;

use uuid::Uuid;

use crate::{
    data_model::{ConnectIssuerRequest, ConnectIssuerResponse},
    error::{OneCoreError, SSIError},
    model::did::DidType,
    repository::{data_provider::CredentialState, error::DataLayerError},
    service::{did::dto::CreateDidRequestDTO, error::ServiceError},
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

        let credential_id = request.credential.to_string();
        let credential = self
            .data_layer
            .get_credential_details(&credential_id)
            .await
            .map_err(|e| match e {
                DataLayerError::RecordNotFound => {
                    OneCoreError::SSIError(SSIError::MissingCredential)
                }
                e => OneCoreError::DataLayerError(e),
            })?;

        if credential.state != CredentialState::Offered {
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
                        organisation_id: Uuid::from_str(&credential.schema.organisation_id)
                            .map_err(|_| {
                                ServiceError::MappingError("Could not convert to UUID".to_string())
                            })?,
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

        self.data_layer
            .update_credential_received_did(&credential_id, &did_id.to_string())
            .await
            .map_err(OneCoreError::DataLayerError)?;

        let token = formatter
            .format_credentials(&credential, &request.did)
            .map_err(OneCoreError::FormatterError)?;

        self.data_layer
            .update_credential_token(&credential_id, token.bytes().collect())
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(ConnectIssuerResponse {
            credential: token,
            format: format.to_owned(),
        })
    }
}
