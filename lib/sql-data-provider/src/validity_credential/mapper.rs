use one_core::model;
use one_core::repository::error::DataLayerError;

use crate::entity::validity_credential;

impl From<model::validity_credential::ValidityCredential> for validity_credential::Model {
    fn from(value: model::validity_credential::ValidityCredential) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date,
            credential: value.credential,
            credential_id: value.linked_credential_id.to_string(),
            r#type: value.r#type.into(),
        }
    }
}

impl TryFrom<validity_credential::Model> for model::validity_credential::ValidityCredential {
    type Error = DataLayerError;

    fn try_from(value: validity_credential::Model) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id.parse()?,
            created_date: value.created_date,
            credential: value.credential,
            linked_credential_id: value.credential_id.parse()?,
            r#type: value.r#type.into(),
        })
    }
}
