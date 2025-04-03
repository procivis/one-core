use serde::{Deserialize, Serialize};

use crate::provider::issuance_protocol::openid4vci_draft13::IssuanceProtocolError;

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<Vec<u8>>,
) -> Result<DataDTO, IssuanceProtocolError> {
    let data = data.as_ref().ok_or(IssuanceProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(IssuanceProtocolError::JsonError)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, IssuanceProtocolError> {
    serde_json::to_vec(&dto).map_err(IssuanceProtocolError::JsonError)
}
