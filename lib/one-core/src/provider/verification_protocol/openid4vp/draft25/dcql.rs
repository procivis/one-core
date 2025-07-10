use convert_case::{Case, Casing};
use dcql::{ClaimQuery, ClaimQueryId, CredentialFormat, CredentialQuery, DcqlQuery};

use crate::common_mapper::NESTED_CLAIM_MARKER;
use crate::config::core_config::FormatType;
use crate::model::credential_schema::CredentialSchema;
use crate::model::proof_schema::{ProofInputClaimSchema, ProofSchema};
use crate::provider::verification_protocol::FormatMapper;
use crate::provider::verification_protocol::error::VerificationProtocolError;

pub fn create_dcql_query(
    proof_schema: &ProofSchema,
    format_to_type_mapper: &FormatMapper,
) -> Result<DcqlQuery, VerificationProtocolError> {
    let input_schemas =
        proof_schema
            .input_schemas
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "Input schemas not found".to_string(),
            ))?;

    let credential_queries =
        input_schemas
            .iter()
            .map(|input_schema| {
                let credential_schema = input_schema.credential_schema.as_ref().ok_or(
                    VerificationProtocolError::Failed("Credential schema not found".to_string()),
                )?;

                let claim_schemas = input_schema.claim_schemas.as_ref().ok_or(
                    VerificationProtocolError::Failed("Claim schemas not found".to_string()),
                )?;

                let credential_format = format_to_type_mapper(&credential_schema.format)?;
                let dcql_format: CredentialFormat = credential_format.into();

                let base_credential_query = match dcql_format {
                    CredentialFormat::MsoMdoc => {
                        CredentialQuery::mso_mdoc(credential_schema.schema_id.clone())
                    }
                    CredentialFormat::SdJwt => {
                        CredentialQuery::sd_jwt_vc(vec![credential_schema.schema_id.clone()])
                    }
                    CredentialFormat::LdpVc => {
                        CredentialQuery::ldp_vc(w3c_credential_query_type_values(credential_schema))
                    }
                    CredentialFormat::JwtVc => {
                        CredentialQuery::jwt_vc(w3c_credential_query_type_values(credential_schema))
                    }
                };

                // Build claim queries
                let claim_queries: Vec<ClaimQuery> = claim_schemas
                    .iter()
                    .map(|claim_schema| {
                        let claim_query_builder = ClaimQuery::builder()
                            .id(claim_schema.schema.id.to_string())
                            .path(format_dcql_path(&claim_schema.schema.key, &dcql_format))
                            .required(claim_schema.required);

                        // Add intent_to_retain for MDOC format
                        match credential_format {
                            FormatType::Mdoc => claim_query_builder.intent_to_retain(true).build(),
                            _ => claim_query_builder.build(),
                        }
                    })
                    .collect();

                // Build final credential query
                Ok(base_credential_query
                    .id(credential_schema.id.to_string())
                    .claims(claim_queries)
                    .maybe_claim_sets(build_claim_sets(claim_schemas))
                    .build())
            })
            .collect::<Result<Vec<_>, VerificationProtocolError>>()?;

    // Build and return final DCQL query
    Ok(DcqlQuery::builder().credentials(credential_queries).build())
}

fn build_claim_sets(claim_schemas: &[ProofInputClaimSchema]) -> Option<Vec<Vec<ClaimQueryId>>> {
    let (required_claims, optional_claims): (Vec<_>, Vec<_>) =
        claim_schemas.iter().partition(|cs| cs.required);

    if optional_claims.is_empty() {
        None
    } else {
        let required_claim_ids: Vec<ClaimQueryId> = required_claims
            .iter()
            .map(|cs| ClaimQueryId::from(cs.schema.id.to_string()))
            .collect();

        let optional_claim_ids: Vec<ClaimQueryId> = optional_claims
            .iter()
            .map(|cs| ClaimQueryId::from(cs.schema.id.to_string()))
            .collect();

        Some(vec![
            [&required_claim_ids[..], &optional_claim_ids[..]].concat(),
            required_claim_ids,
        ])
    }
}

fn w3c_credential_query_type_values(credential_schema: &CredentialSchema) -> Vec<Vec<String>> {
    let credential_type = credential_schema.name.to_case(Case::Pascal);
    vec![
        vec![
            "https://www.w3.org/2018/credentials#VerifiableCredential".to_string(),
            format!("{}#{}", credential_schema.schema_id, credential_type),
        ],
        vec![credential_type],
    ]
}

fn format_dcql_path<'a>(claim_key: &'a str, dcql_format: &dcql::CredentialFormat) -> Vec<&'a str> {
    let key_split = claim_key.split(NESTED_CLAIM_MARKER).collect::<Vec<_>>();

    match dcql_format {
        CredentialFormat::LdpVc | CredentialFormat::JwtVc => {
            [&["credentialSubject"], &key_split[..]].concat()
        }
        _ => key_split,
    }
}

impl From<FormatType> for dcql::CredentialFormat {
    fn from(value: FormatType) -> Self {
        match value {
            FormatType::Jwt => CredentialFormat::JwtVc,
            FormatType::PhysicalCard => CredentialFormat::LdpVc,
            FormatType::SdJwt => CredentialFormat::SdJwt,
            FormatType::SdJwtVc => CredentialFormat::SdJwt,
            FormatType::JsonLdClassic => CredentialFormat::LdpVc,
            FormatType::JsonLdBbsPlus => CredentialFormat::LdpVc,
            FormatType::Mdoc => CredentialFormat::MsoMdoc,
        }
    }
}
