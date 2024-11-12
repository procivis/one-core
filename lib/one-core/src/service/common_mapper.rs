use uuid::Uuid;

use crate::model::credential_schema::CredentialSchema;

pub(crate) fn regenerate_credential_schema_uuids(
    mut credential_schema: CredentialSchema,
) -> CredentialSchema {
    credential_schema.id = Uuid::new_v4().into();
    if let Some(claim_schemas) = credential_schema.claim_schemas.as_mut() {
        claim_schemas.iter_mut().for_each(|schema| {
            schema.schema.id = Uuid::new_v4().into();
        })
    }

    credential_schema
}
