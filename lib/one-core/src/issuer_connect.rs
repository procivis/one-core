use crate::{
    data_layer::{data_model::CredentialState, DataLayerError},
    data_model::{ConnectIssuerRequest, ConnectIssuerResponse},
    error::{OneCoreError, SSIError},
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

        // This will later be replaced by a string format in the database
        let format = match credential.schema.format {
            crate::data_layer::data_model::Format::Jwt => "JWT",
            crate::data_layer::data_model::Format::SdJwt => "SD-JWT",
            crate::data_layer::data_model::Format::JsonLd => "JSON-LD",
            crate::data_layer::data_model::Format::Mdoc => "MDOC",
        };

        let formatter = self.get_formatter(format)?;

        let did_id = match self.data_layer.get_did_details_by_value(&request.did).await {
            Ok(did) => did.id,
            Err(DataLayerError::RecordNotFound) => self
                .data_layer
                .insert_remote_did(&request.did, &credential.schema.organisation_id)
                .await
                .map_err(OneCoreError::DataLayerError)?,
            Err(e) => {
                return Err(OneCoreError::DataLayerError(e));
            }
        };

        self.data_layer
            .update_credential_received_did(&credential_id, &did_id)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        let token = formatter
            .format(&credential, &request.did)
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

// testcases
// wrong state
