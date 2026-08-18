use shared_types::{CredentialSchemaId, ProofSchemaId};

use super::EudiEcosystem;
use super::mapper::credential_schema_to_schema_format;
use crate::config::core_config::{CoreConfig, KeyAlgorithmType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::openid4vp::format_type_to_dcql_format;
use crate::model::certificate::CertificateRole;
use crate::model::credential_schema::CredentialSchema;
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
                    Some(SchemaFilter::CredentialSchema(credential_schema_id)) => Some(
                        self.credential_schema_filter(credential_schema_id, TrustContext::Issuance)
                            .await?,
                    ),
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
                        let schema = self
                            .credential_schema_repository
                            .get_credential_schema(credential_schema_id)
                            .await
                            .error_while("getting credential schema")?;
                        let (schema_format, _) =
                            credential_schema_to_schema_format(&schema, &self.config).await?;

                        if !all_pid_schema_formats.contains(&schema_format) {
                            return Err(EcosystemError::InvalidRoleFilter {
                                role,
                                filter: filter.to_owned(),
                            }
                            .error_while("checking schema is PID")
                            .into());
                        }

                        vec![schema_format]
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
                let schema_condition = match schema_filter {
                    None => None,
                    Some(SchemaFilter::ProofSchema(proof_schema_id)) => {
                        Some(self.proof_schema_filter(proof_schema_id).await?)
                    }
                    Some(SchemaFilter::CredentialSchema(credential_schema_id)) => Some(
                        self.credential_schema_filter(
                            credential_schema_id,
                            TrustContext::Verification,
                        )
                        .await?
                        .condition(),
                    ),
                };

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

    async fn credential_schema_filter(
        &self,
        credential_schema_id: &CredentialSchemaId,
        context: TrustContext,
    ) -> Result<IdentifierFilterValue, EcosystemError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;
        let filter_value =
            filter_value_from_credential_schema(&schema, &self.config, context).await?;
        Ok(filter_value)
    }

    async fn proof_schema_filter(
        &self,
        proof_schema_id: &ProofSchemaId,
    ) -> Result<ListFilterCondition<IdentifierFilterValue>, EcosystemError> {
        let schema = self
            .proof_schema_repository
            .get_proof_schema(proof_schema_id)
            .await
            .error_while("getting proof schema")?;
        let mut trust_verification_types = ListFilterCondition::<IdentifierFilterValue>::default();
        let input_schemas = schema.input_schemas.as_ref().await?;
        for input_schema in &input_schemas {
            let credential_schema = input_schema.credential_schema.as_ref().await?;
            let filter_value = filter_value_from_credential_schema(
                &credential_schema,
                &self.config,
                TrustContext::Verification,
            )
            .await?;
            trust_verification_types = trust_verification_types & filter_value;
        }
        Ok(trust_verification_types)
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

enum TrustContext {
    Issuance,
    Verification,
}

async fn filter_value_from_credential_schema(
    schema: &CredentialSchema,
    config: &CoreConfig,
    context: TrustContext,
) -> Result<IdentifierFilterValue, EcosystemError> {
    let (schema_format, _) = credential_schema_to_schema_format(schema, config).await?;
    Ok(match context {
        TrustContext::Issuance => IdentifierFilterValue::TrustAllowedIssuanceTypes(schema_format),
        TrustContext::Verification => {
            IdentifierFilterValue::TrustAllowedVerificationTypes(schema_format)
        }
    })
}
