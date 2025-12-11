use one_dto_mapper::From;
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display};

use crate::model::revocation_list::RevocationListPurpose;

#[derive(Debug, Serialize, Deserialize, From, AsRefStr, Display)]
#[serde(rename_all = "camelCase")]
#[from(RevocationListPurpose)]
pub enum StatusPurpose {
    #[strum(serialize = "revocation")]
    Revocation,
    #[strum(serialize = "suspension")]
    Suspension,
    #[strum(serialize = "revocation_and_suspension")]
    RevocationAndSuspension,
}
