use shared_types::OrganisationId;

use super::Error;
use crate::config::core_config::{ConfigExt, CoreConfig};
use crate::error::ContextWithErrorCode;
use crate::model::list_filter::{ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::proof_schema::ProofSchemaListQuery;
use crate::repository::proof_schema_repository::ProofSchemaRepository;
use crate::service::proof_schema::dto::{
    ImportProofSchemaClaimSchemaDTO, ImportProofSchemaDTO, ProofSchemaFilterValue,
};

pub(crate) async fn proof_schema_name_already_exists(
    repository: &dyn ProofSchemaRepository,
    name: &str,
    organisation_id: OrganisationId,
) -> Result<(), Error> {
    let proof_schemas = repository
        .get_proof_schema_list(create_unique_name_check_request(name, organisation_id))
        .await
        .error_while("getting proof schemas")?;
    if !proof_schemas.values.is_empty() {
        return Err(Error::AlreadyExists);
    }
    Ok(())
}

pub(super) fn validate_imported_proof_schema(
    schema: &ImportProofSchemaDTO,
    config: &CoreConfig,
) -> Result<(), Error> {
    for schema in &schema.proof_input_schemas {
        let format = &schema.credential_schema.format;
        config
            .format
            .get_if_enabled(format)
            .map_err(|_| Error::UnsupportedFormat(format.to_owned()))?;

        validate_imported_proof_schema_data_types(&schema.claim_schemas, config)?;
    }

    Ok(())
}

fn validate_imported_proof_schema_data_types(
    claim_schemas: &[ImportProofSchemaClaimSchemaDTO],
    config: &CoreConfig,
) -> Result<(), Error> {
    for claim_schema in claim_schemas {
        let datatype = &claim_schema.data_type;
        config
            .datatype
            .get_if_enabled(datatype)
            .map_err(|_| Error::UnsupportedDatatype(datatype.to_owned()))?;

        validate_imported_proof_schema_data_types(&claim_schema.claims, config)?;
    }

    Ok(())
}

fn create_unique_name_check_request(
    name: &str,
    organisation_id: OrganisationId,
) -> ProofSchemaListQuery {
    ProofSchemaListQuery {
        include_count: false,
        pagination: Some(ListPagination {
            page: 0,
            page_size: 1,
        }),
        filtering: Some(
            ProofSchemaFilterValue::OrganisationId(organisation_id).condition()
                & ProofSchemaFilterValue::Name(StringMatch::equals(name.to_string())),
        ),
        ..Default::default()
    }
}
