use self::helpers::{extract_jwk, generate_document};

use super::{dto::DidDocumentDTO, DidMethodError};
use crate::model::key::Key;

use async_trait::async_trait;
use shared_types::{DidId, DidValue};

mod helpers;

pub struct JWKMethod {}

impl JWKMethod {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl super::DidMethod for JWKMethod {
    fn get_method(&self) -> String {
        "JWK".to_string()
    }

    async fn create(
        &self,
        _id: &DidId,
        _params: &Option<serde_json::Value>,
        _key: &Option<Key>,
    ) -> Result<DidValue, DidMethodError> {
        todo!()
    }

    fn check_authorization(&self) -> bool {
        todo!()
    }

    async fn resolve(&self, did: &DidValue) -> Result<DidDocumentDTO, DidMethodError> {
        let jwk = extract_jwk(did)?;
        Ok(generate_document(did, jwk))
    }

    fn update(&self) -> Result<(), DidMethodError> {
        Err(DidMethodError::NotSupported)
    }

    fn can_be_deactivated(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod test;
