use shared_types::ClaimSchemaId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::CredentialSchemaClaim;
use crate::provider::credential_formatter::MetadataClaimSchema;

pub(crate) fn claim_schema_from_metadata_claim_schema(
    metadata_claim: MetadataClaimSchema,
    now: OffsetDateTime,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id: Uuid::new_v4().into(),
            key: metadata_claim.key,
            data_type: metadata_claim.data_type,
            created_date: now,
            last_modified: now,
            array: metadata_claim.array,
            metadata: true,
        },
        required: metadata_claim.required,
    }
}

pub(crate) fn from_jwt_request_claim_schema(
    now: OffsetDateTime,
    id: ClaimSchemaId,
    key: String,
    datatype: String,
    required: bool,
    array: Option<bool>,
) -> CredentialSchemaClaim {
    CredentialSchemaClaim {
        schema: ClaimSchema {
            id,
            key,
            data_type: datatype,
            created_date: now,
            last_modified: now,
            array: array.unwrap_or(false),
            metadata: false,
        },
        required,
    }
}
