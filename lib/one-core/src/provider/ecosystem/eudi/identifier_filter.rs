use shared_types::{CredentialSchemaId, ProofSchemaId};

use super::EudiEcosystem;
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::identifier_trust_information::{
    credential_schema_to_schema_formats, proof_schema_to_schema_formats,
};
use crate::mapper::openid4vp::format_type_to_dcql_format;
use crate::model::certificate::CertificateRole;
use crate::model::identifier::IdentifierType;
use crate::model::identifier_trust_information::SchemaFormat;
use crate::model::list_filter::{ListFilterCondition, ListFilterValue};
use crate::provider::ecosystem::IdentifierFilterValue;
use crate::provider::ecosystem::error::EcosystemError;
use crate::provider::ecosystem::model::{EcosystemRole, SchemaFilter};

impl EudiEcosystem {
    pub(super) async fn get_filter(
        &self,
        role: EcosystemRole,
        schema_filter: Option<&SchemaFilter>,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        Ok(match role {
            EcosystemRole::Holder => {
                if let Some(filter @ SchemaFilter::ProofSchema(_)) = schema_filter {
                    return Err(EcosystemError::InvalidRoleFilter {
                        role,
                        filter: filter.to_owned(),
                    });
                }

                IdentifierFilterValue::Types(vec![IdentifierType::Certificate, IdentifierType::Key])
                    .condition()
                    & supported_key_algorithms()
            }
            EcosystemRole::Issuer => {
                let schema_condition = match schema_filter {
                    None => None,
                    Some(filter @ SchemaFilter::ProofSchema(_)) => {
                        return Err(EcosystemError::InvalidRoleFilter {
                            role,
                            filter: filter.to_owned(),
                        });
                    }
                    Some(SchemaFilter::CredentialSchema(credential_schema_id)) => {
                        Some(IdentifierFilterValue::trust_allowed_issuance_types(
                            self.credential_schema_formats(credential_schema_id).await?,
                        ))
                    }
                };

                IdentifierFilterValue::Types(vec![IdentifierType::Certificate]).condition()
                    & IdentifierFilterValue::CertificateRole(CertificateRole::Authentication)
                    & IdentifierFilterValue::CertificateRole(CertificateRole::AssertionMethod)
                    & supported_key_algorithms()
                    & schema_condition
            }
            EcosystemRole::PidProvider => {
                let all_pid_schema_formats = self.pid_schema_formats()?;
                let schema_formats = match schema_filter {
                    None => all_pid_schema_formats,
                    Some(filter @ SchemaFilter::ProofSchema(_)) => {
                        return Err(EcosystemError::InvalidRoleFilter {
                            role,
                            filter: filter.to_owned(),
                        });
                    }
                    Some(filter @ SchemaFilter::CredentialSchema(credential_schema_id)) => {
                        let schema_formats =
                            self.credential_schema_formats(credential_schema_id).await?;

                        if !schema_formats
                            .iter()
                            .all(|schema_format| all_pid_schema_formats.contains(schema_format))
                        {
                            return Err(EcosystemError::InvalidRoleFilter {
                                role,
                                filter: filter.to_owned(),
                            }
                            .error_while("checking schema is PID")
                            .into());
                        }

                        schema_formats
                    }
                };

                let schema_condition = ListFilterCondition::Or(
                    schema_formats
                        .into_iter()
                        .map(IdentifierFilterValue::TrustAllowedIssuanceTypes)
                        .map(ListFilterCondition::from)
                        .collect(),
                );

                IdentifierFilterValue::Types(vec![IdentifierType::Certificate]).condition()
                    & IdentifierFilterValue::CertificateRole(CertificateRole::AssertionMethod)
                    & supported_key_algorithms()
                    & schema_condition
            }
            EcosystemRole::Verifier => {
                let schema_formats = match schema_filter {
                    None => None,
                    Some(SchemaFilter::ProofSchema(proof_schema_id)) => {
                        Some(self.proof_schema_formats(proof_schema_id).await?)
                    }
                    Some(SchemaFilter::CredentialSchema(credential_schema_id)) => {
                        Some(self.credential_schema_formats(credential_schema_id).await?)
                    }
                };
                let schema_condition =
                    schema_formats.map(IdentifierFilterValue::trust_allowed_verification_types);

                IdentifierFilterValue::Types(vec![IdentifierType::Certificate]).condition()
                    & IdentifierFilterValue::CertificateRole(CertificateRole::Authentication)
                    & supported_key_algorithms()
                    & schema_condition
            }

            EcosystemRole::NationalRegistryRegistrar => {
                if let Some(filter) = schema_filter {
                    return Err(EcosystemError::InvalidRoleFilter {
                        role,
                        filter: filter.to_owned(),
                    });
                }

                IdentifierFilterValue::Types(vec![IdentifierType::Certificate]).condition()
                    & supported_key_algorithms()
            }
            EcosystemRole::WalletProvider => {
                if let Some(filter) = schema_filter {
                    return Err(EcosystemError::InvalidRoleFilter {
                        role,
                        filter: filter.to_owned(),
                    });
                }

                IdentifierFilterValue::Types(vec![IdentifierType::Certificate, IdentifierType::Key])
                    .condition()
                    & supported_key_algorithms()
            }
        })
    }

    async fn credential_schema_formats(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<Vec<SchemaFormat>, EcosystemError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;
        Ok(credential_schema_to_schema_formats(&schema, &self.config).await?)
    }

    async fn proof_schema_formats(
        &self,
        proof_schema_id: &ProofSchemaId,
    ) -> Result<Vec<SchemaFormat>, EcosystemError> {
        let schema = self
            .proof_schema_repository
            .get_proof_schema(proof_schema_id)
            .await
            .error_while("getting proof schema")?;
        Ok(proof_schema_to_schema_formats(&schema, &self.config).await?)
    }

    fn pid_schema_formats(&self) -> Result<Vec<SchemaFormat>, EcosystemError> {
        let mut result = vec![];

        for schema in &self.params.credential_schemas {
            let format_type = self
                .config
                .format
                .get_type(&schema.format)
                .error_while("checking credential schema format")?;
            let format = format_type_to_dcql_format(&format_type);

            for pid_schema_id in &schema.pid_schema_ids {
                result.push(SchemaFormat {
                    format: format.to_owned(),
                    schema_id: pid_schema_id.to_owned(),
                })
            }
        }

        Ok(result)
    }
}

fn supported_key_algorithms() -> IdentifierFilterValue {
    IdentifierFilterValue::KeyAlgorithms(vec![
        KeyAlgorithmType::Eddsa.to_string(),
        KeyAlgorithmType::Ecdsa.to_string(),
    ])
}
