use serde::{Deserialize, Serialize};

use crate::provider::revocation::model::RevocationListId;

#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationUpdateData {
    pub id: RevocationListId,
    pub value: Vec<u8>,
}
