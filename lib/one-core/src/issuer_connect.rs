use crate::{
    data_layer::{
        data_model::{CreateDidRequest, CredentialState, DidMethod, DidType},
        DataLayerError,
    },
    data_model::{ConnectRequest, ConnectResponse},
    error::{OneCoreError, SSIError},
    OneCore,
};

impl OneCore {
    pub async fn issuer_connect(
        &self,
        transport_protocol: &str,
        request: &ConnectRequest,
    ) -> Result<ConnectResponse, OneCoreError> {
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

        // This will later be replaced by a string format in the database
        let format = match credential.schema.format {
            crate::data_layer::data_model::Format::Jwt => "JWT",
            crate::data_layer::data_model::Format::SdJwt => "SD-JWT",
            crate::data_layer::data_model::Format::JsonLd => "JSON-LD",
            crate::data_layer::data_model::Format::Mdoc => "MDOC",
        };

        let formatter = self.get_formatter(format)?;

        let did_insert_result = self
            .data_layer
            .create_did(CreateDidRequest {
                name: "NEW_DID_FIXME".to_string(),
                organisation_id: credential.schema.organisation_id.clone(),
                did: request.did.clone(),
                did_type: DidType::Remote,
                did_method: DidMethod::Web,
            })
            .await;

        match did_insert_result {
            Ok(did) => self
                .data_layer
                .update_credential_received_did(&credential_id, &did.id)
                .await
                .map_err(OneCoreError::DataLayerError)?,
            Err(DataLayerError::AlreadyExists) => {}
            Err(e) => return Err(OneCoreError::DataLayerError(e)),
        }

        let token = formatter
            .format(&credential, &request.did)
            .map_err(OneCoreError::FormatterError)?;

        self.data_layer
            .update_credential_token(&credential_id, token.bytes().collect())
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(ConnectResponse {
            credential: token,
            format: format.to_owned(),
        })
    }
}

// testcases
// wrong state
