use one_core::model::claim_schema::ClaimSchema;

use crate::entity::claim_schema;
use crate::localized_text::localized_texts;
use crate::transaction_context::TransactionManagerImpl;

pub(crate) fn claim_schema_from_model(
    value: claim_schema::Model,
    db: TransactionManagerImpl,
) -> ClaimSchema {
    ClaimSchema {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        key: value.key,
        data_type: value.datatype,
        array: value.array,
        metadata: value.metadata,
        required: value.required,
        translations: localized_texts(value.id.into(), db),
    }
}
