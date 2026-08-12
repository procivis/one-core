use shared_types::OrganisationId;

use super::EudiEcosystem;
use super::mapper::formatter_requires_namespaces;
use crate::error::ContextWithErrorCode;
use crate::model::credential::Credential;
use crate::proto::wrp_validator::credential_category;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::error::EcosystemError;

impl EudiEcosystem {
    pub(super) async fn resolve_verifier_submission(
        &self,
        credential: &Credential,
        issuer_details: &IdentifierDetails,
        organisation_id: OrganisationId,
    ) -> Result<(), EcosystemError> {
        let schema = credential.schema.as_ref().await?;
        let format = schema.format().await?;
        let formatter = self.formatter_provider.get_credential_formatter(&format)?;

        let namespaced = formatter_requires_namespaces(formatter.as_ref());
        let claims = credential.claims.as_ref().await?;
        let category = credential_category(&claims, namespaced);

        let IdentifierDetails::Certificate(issuer_certificate) = issuer_details else {
            return Err(EcosystemError::MissingIdentifier);
        };

        self.wrp_validator
            .validate_credential_issuer(
                Some(&issuer_certificate.chain),
                &schema,
                category,
                issuer_certificate.x5_references,
                organisation_id,
            )
            .await
            .error_while("validating credential issuer")?;

        Ok(())
    }
}
