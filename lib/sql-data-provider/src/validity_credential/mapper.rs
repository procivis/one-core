use one_core::{model, repository::error::DataLayerError};

use crate::entity::validity_credential::{self, ValidityCredentialType};

impl From<model::lvvc::Lvvc> for validity_credential::Model {
    fn from(value: model::lvvc::Lvvc) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date,
            credential: value.credential,
            credential_id: value.linked_credential_id.to_string(),
            r#type: ValidityCredentialType::Lvvc,
        }
    }
}

impl TryFrom<validity_credential::Model> for model::lvvc::Lvvc {
    type Error = DataLayerError;

    fn try_from(value: validity_credential::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id.parse()?,
            created_date: value.created_date,
            credential: value.credential,
            linked_credential_id: value.credential_id.parse()?,
        })
    }
}
