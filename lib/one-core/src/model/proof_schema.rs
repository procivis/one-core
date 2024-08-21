use dto_mapper::{convert_inner, convert_inner_of_inner, From, Into};
use one_providers::common_models::organisation::OpenOrganisation;
use one_providers::common_models::proof_schema::{OpenProofInputSchema, OpenProofSchema};
use shared_types::ProofSchemaId;
use time::OffsetDateTime;

use crate::service::error::ServiceError;

use super::claim_schema::ClaimSchema;
use super::common::{GetListQueryParams, GetListResponse};
use super::credential_schema::{
    to_open_credential_schema, CredentialSchema, CredentialSchemaRelations,
};
use super::organisation::Organisation;
use super::relation::{FailingRelationLoader, Related};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofSchema {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,

    // Relations
    pub organisation: Related<Organisation>,
    pub input_schemas: Option<Vec<ProofInputSchema>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default, From)]
#[from(OpenProofInputSchema)]
pub struct ProofInputSchema {
    pub validity_constraint: Option<i64>,

    // Relations
    #[from(with_fn = "convert_inner_of_inner")]
    pub claim_schemas: Option<Vec<ProofInputClaimSchema>>,
    #[from(with_fn = "convert_inner")]
    pub credential_schema: Option<CredentialSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From)]
#[into(one_providers::common_models::proof_schema::OpenProofInputClaimSchema)]
#[from(one_providers::common_models::proof_schema::OpenProofInputClaimSchema)]
pub struct ProofInputClaimSchema {
    pub schema: ClaimSchema,
    pub required: bool,
    pub order: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

pub type GetProofSchemaList = GetListResponse<ProofSchema>;
pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumn>;

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofSchemaRelations {
    pub proof_inputs: Option<ProofInputSchemaRelations>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofSchemaClaimRelations {}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct ProofInputSchemaRelations {
    pub claim_schemas: Option<ProofSchemaClaimRelations>,
    pub credential_schema: Option<CredentialSchemaRelations>,
}

impl From<OpenProofSchema> for ProofSchema {
    fn from(value: OpenProofSchema) -> Self {
        Self {
            id: value.id.into(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            deleted_at: value.deleted_at,
            name: value.name,
            expire_duration: value.expire_duration,
            organisation: Related::from_loader(
                value.organisation.unwrap().id.into(),
                Box::new(FailingRelationLoader),
            ),
            input_schemas: convert_inner_of_inner(value.input_schemas),
        }
    }
}

pub(crate) async fn to_open_proof_schema(
    value: ProofSchema,
) -> Result<OpenProofSchema, ServiceError> {
    let input_schemas = if let Some(schemas) = value.input_schemas {
        let mut result: Vec<OpenProofInputSchema> = vec![];
        for schema in schemas {
            result.push(to_open_proof_input_schema(schema).await?);
        }
        Some(result)
    } else {
        None
    };

    Ok(OpenProofSchema {
        id: value.id.into(),
        created_date: value.created_date,
        last_modified: value.last_modified,
        deleted_at: value.deleted_at,
        name: value.name,
        expire_duration: value.expire_duration,
        organisation: Some(OpenOrganisation {
            id: (*value.organisation.id()).into(),
        }),
        input_schemas,
    })
}

pub(crate) async fn to_open_proof_input_schema(
    value: ProofInputSchema,
) -> Result<OpenProofInputSchema, ServiceError> {
    let credential_schema = if let Some(schema) = value.credential_schema {
        Some(to_open_credential_schema(schema).await?)
    } else {
        None
    };
    Ok(OpenProofInputSchema {
        validity_constraint: value.validity_constraint,
        claim_schemas: convert_inner_of_inner(value.claim_schemas),
        credential_schema,
    })
}
