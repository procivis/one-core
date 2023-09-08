use std::str::FromStr;
use uuid::Uuid;

use crate::local_did_helpers::{get_first_local_did, get_first_organisation_id};
use crate::service::error::ServiceError;
use crate::{
    error::{OneCoreError, SSIError},
    OneCore,
};

impl OneCore {
    pub async fn holder_submit_proof(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &str,
        credential_ids: &[String],
    ) -> Result<(), OneCoreError> {
        // FIXME - these two should be fetched correctly
        let organisation_id = get_first_organisation_id(&self.organisation_repository).await?;
        let holder_did = get_first_local_did(&self.data_layer, &organisation_id).await?;

        // FIXME - pick correct formatter
        let formatter = self.get_formatter("JWT")?;

        let mut credentials: Vec<String> = vec![];
        for credential_id in credential_ids {
            let uuid = Uuid::from_str(credential_id).map_err(|_| {
                OneCoreError::ServiceError(ServiceError::MappingError(format!(
                    "{credential_id} is not UUID"
                )))
            })?;
            let credential_data = self
                .credential_service
                .get_credential(&uuid)
                .await?
                .credential;

            if credential_data.is_empty() {
                return Err(OneCoreError::SSIError(SSIError::MissingCredential));
            }
            let credential_content = std::str::from_utf8(&credential_data)
                .map_err(|_| OneCoreError::SSIError(SSIError::MissingCredential))?;

            credentials.push(credential_content.to_owned());
        }

        let presentation = formatter.format_presentation(&credentials, &holder_did.did)?;

        self.get_transport_protocol(transport_protocol)?
            .submit_proof(base_url, proof_id, &presentation)
            .await
            .map_err(|e| OneCoreError::SSIError(SSIError::TransportProtocolError(e)))
    }
}
