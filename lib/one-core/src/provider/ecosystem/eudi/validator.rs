use super::EudiEcosystem;
use crate::config::core_config::FormatType;
use crate::mapper::identifier_trust_information::{
    credential_schema_to_schema_formats, proof_schema_to_schema_formats,
};
use crate::mapper::openid4vp::format_type_to_dcql_format;
use crate::model::credential::Credential;
use crate::model::identifier::IdentifierData;
use crate::model::proof::Proof;
use crate::provider::ecosystem::EcosystemError;

const ALLOWED_FORMAT_TYPES: &[FormatType] = &[FormatType::Mdoc, FormatType::SdJwtVc];

impl EudiEcosystem {
    pub(super) async fn validate_credential_creation(
        &self,
        credential: &Credential,
    ) -> Result<(), EcosystemError> {
        let issuer = credential.issuer()?.data;
        let issuer_identifier = issuer.identifier.as_ref().await?;

        if !matches!(issuer_identifier.data, IdentifierData::Certificate(_)) {
            return Err(EcosystemError::InvalidIdentifier(issuer_identifier.id));
        }

        let Some(_issuer_certificate) = &issuer.certificate else {
            return Err(EcosystemError::MissingIdentifier);
        };

        let credential_schema = credential.common().schema.as_ref().await?;
        let reg_certs = issuer_identifier.trust_information.as_ref().await?;
        let allowed_formats = allowed_formats();
        for schema_format in
            credential_schema_to_schema_formats(&credential_schema, &self.config).await?
        {
            if !allowed_formats.contains(&schema_format.format) {
                return Err(EcosystemError::DisallowedSchemaFormat(schema_format));
            }

            if reg_certs
                .iter()
                .any(|reg_cert| !reg_cert.allowed_issuance_types.contains(&schema_format))
            {
                return Err(EcosystemError::DisallowedSchemaFormat(schema_format));
            }
        }

        Ok(())
    }

    pub(super) async fn validate_proof_creation(
        &self,
        proof: &Proof,
    ) -> Result<(), EcosystemError> {
        let Some(verifier_identifier) = &proof.verifier_identifier else {
            return Err(EcosystemError::MissingIdentifier);
        };
        let verifier_identifier = verifier_identifier.as_ref().await?;

        if !matches!(verifier_identifier.data, IdentifierData::Certificate(_)) {
            return Err(EcosystemError::InvalidIdentifier(verifier_identifier.id));
        }

        let Some(_verifier_certificate) = &proof.verifier_certificate else {
            return Err(EcosystemError::MissingIdentifier);
        };

        let Some(proof_schema) = &proof.schema else {
            return Err(EcosystemError::MappingError(
                "Missing proof schema".to_string(),
            ));
        };
        let proof_schema = proof_schema.as_ref().await?;
        let reg_certs = verifier_identifier.trust_information.as_ref().await?;
        let allowed_formats = allowed_formats();
        for schema_format in proof_schema_to_schema_formats(&proof_schema, &self.config).await? {
            if !allowed_formats.contains(&schema_format.format) {
                return Err(EcosystemError::DisallowedSchemaFormat(schema_format));
            }

            if reg_certs
                .iter()
                .any(|reg_cert| !reg_cert.allowed_verification_types.contains(&schema_format))
            {
                return Err(EcosystemError::DisallowedSchemaFormat(schema_format));
            }
        }

        Ok(())
    }
}

fn allowed_formats() -> Vec<String> {
    ALLOWED_FORMAT_TYPES
        .iter()
        .map(format_type_to_dcql_format)
        .collect()
}
