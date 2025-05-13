use one_core::model::certificate::Certificate;
use sea_orm::Set;

use crate::entity::certificate::{self, ActiveModel};

impl From<Certificate> for ActiveModel {
    fn from(certificate: Certificate) -> Self {
        let key_id = certificate.key.map(|key| key.id);

        Self {
            id: Set(certificate.id),
            identifier_id: Set(certificate.identifier_id),
            created_date: Set(certificate.created_date),
            last_modified: Set(certificate.last_modified),
            expiry_date: Set(certificate.expiry_date),
            name: Set(certificate.name),
            chain: Set(certificate.chain),
            state: Set(certificate.state.into()),
            key_id: Set(key_id),
        }
    }
}

impl From<certificate::Model> for Certificate {
    fn from(value: certificate::Model) -> Self {
        Self {
            id: value.id,
            identifier_id: value.identifier_id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            expiry_date: value.expiry_date,
            name: value.name,
            chain: value.chain,
            state: value.state.into(),
            key: None,
        }
    }
}
