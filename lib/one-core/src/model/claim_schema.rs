use proc_macros::Model;
use shared_types::ClaimSchemaId;
use time::OffsetDateTime;

use crate::model::localized_text::LocalizedText;
use crate::model::relation::RelatedVec;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ClaimSchema {
    #[model(id)]
    pub id: ClaimSchemaId,
    pub key: String,
    pub data_type: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub array: bool,
    pub metadata: bool,
    /// mandatory during issuance
    pub required: bool,

    pub translations: RelatedVec<LocalizedText>,
}
