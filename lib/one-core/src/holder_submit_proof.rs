use crate::error::SSIError;
use crate::local_did_helpers::{get_first_local_did, get_first_organisation_id};
use crate::{error::OneCoreError, OneCore};

impl OneCore {
    pub async fn holder_submit_proof(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &str,
        credential_ids: &[String],
    ) -> Result<(), OneCoreError> {
        // FIXME - these two should be fetched correctly
        let organisation_id = get_first_organisation_id(&self.data_layer).await?;
        let holder_did = get_first_local_did(&self.data_layer, &organisation_id).await?;

        // FIXME - pick correct formatter
        let formatter = self.get_formatter("JWT")?;

        let mut credentials: Vec<String> = vec![];
        for credential_id in credential_ids {
            let credential_data = self
                .data_layer
                .get_credential_details(credential_id)
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
